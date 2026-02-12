from dataclasses import dataclass
from itertools import count
from pathlib import Path
from typing import Any, Dict, List, Optional, Type
import logging
import sys

import volatility3.plugins
from volatility3.cli import text_renderer
from volatility3.framework import automagic, contexts, interfaces, plugins, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import cmdline, dlllist, info, malfind, netscan, pslist, svcscan
from volatility3.plugins.windows.registry import hivelist
from rich.console import Console
from rich.progress import Progress
from rich.table import Table


@dataclass
class ServiceInfo:
    name: str
    display_name: str
    type: str
    state: str
    start: str
    pid: Optional[int]
    binary: Optional[str]
    service_dll: Optional[str]


@dataclass
class DllInfo:
    pid: int
    base: int
    size: int
    name: str
    path: str


@dataclass
class MalfindInfo:
    pid: int
    start: int
    size: int
    protection: str
    commit: str
    tag: str
    notes: Optional[str]
    hexdump: str


@dataclass
class RegistryHive:
    name: str
    path: str
    offset: int
    file_output: Optional[str]


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    offset: int
    threads: int
    handles: int
    start_time: str
    exit_time: Optional[str]


@dataclass
class NetworkConnection:
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: Optional[int]
    owner: Optional[str]


class MemoryDumpAnalyzer:
    def __init__(self, dump_path: Optional[str] = None, demo_mode: bool = False) -> None:
        self.dump_path = Path(dump_path).expanduser() if dump_path else None
        self.demo_mode = demo_mode
        self.console = Console()
        self.context: Optional[interfaces.context.ContextInterface] = None
        self.automagics: List[interfaces.automagic.AutomagicInterface] = []
        self._plugin_run_counter = count()
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging for the analysis."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("memory_analysis.log"),
                logging.StreamHandler(),
            ],
        )

    def initialize_context(self) -> bool:
        """Initialize Volatility context for the memory dump."""
        if self.dump_path is None:
            logging.error("No memory dump path was provided")
            return False

        try:
            resolved_path = self.dump_path.resolve(strict=True)
        except FileNotFoundError:
            logging.error(f"Memory dump not found: {self.dump_path}")
            return False

        try:
            self.context = contexts.Context()
            self.context.config[
                "automagic.LayerStacker.single_location"
            ] = requirements.URIRequirement.location_from_file(str(resolved_path))
            self.automagics = automagic.available(self.context)
            return True
        except Exception as e:
            logging.error(f"Failed to initialize Volatility context: {e}")
            return False

    def _normalize_value(self, value: Any) -> Any:
        """Convert Volatility renderer values into plain Python values."""
        if isinstance(value, interfaces.renderers.BaseAbsentValue):
            return None
        if isinstance(value, renderers.LayerData):
            return text_renderer.CLIRenderer._type_renderers[renderers.LayerData](
                value
            ).strip()
        if isinstance(value, renderers.Disassembly):
            return text_renderer.display_disassembly(value).strip()
        if isinstance(value, bytes):
            return text_renderer.hex_bytes_as_text(value).strip()
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return int(value)
        if value is None:
            return None
        return str(value)

    def _treegrid_to_rows(
        self, treegrid: interfaces.renderers.TreeGrid
    ) -> List[Dict[str, Any]]:
        """Collect a TreeGrid into a list of row dictionaries."""
        columns = [column.name for column in treegrid.columns]
        rows: List[Dict[str, Any]] = []

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: List[Dict[str, Any]],
        ) -> List[Dict[str, Any]]:
            accumulator.append(
                {
                    column: self._normalize_value(value)
                    for column, value in zip(columns, node.values)
                }
            )
            return accumulator

        treegrid.populate(visitor, rows)
        return rows

    def _run_plugin(
        self,
        plugin_class: Type[interfaces.plugins.PluginInterface],
        plugin_config: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Construct and run a Volatility plugin, returning normalized rows."""
        if self.context is None:
            raise RuntimeError("Volatility context has not been initialized")

        base_config_path = interfaces.configuration.path_join(
            "plugins", f"run_{next(self._plugin_run_counter)}"
        )

        for key, value in (plugin_config or {}).items():
            config_path = interfaces.configuration.path_join(
                base_config_path, plugin_class.__name__, key
            )
            self.context.config[config_path] = value

        selected_automagics = automagic.choose_automagic(
            self.automagics, plugin_class
        )
        constructed_plugin = plugins.construct_plugin(
            self.context,
            selected_automagics,
            plugin_class,
            base_config_path,
            None,
            None,
        )
        return self._treegrid_to_rows(constructed_plugin.run())

    async def get_os_info(self) -> Dict[str, Any]:
        """Retrieve operating system information from the memory dump."""
        try:
            rows = self._run_plugin(info.Info)
            return {
                row["Variable"]: row["Value"]
                for row in rows
                if row.get("Variable") and row.get("Value") is not None
            }
        except Exception as e:
            logging.error(f"Error getting OS information: {e}")
            return {}

    async def get_processes(self) -> List[ProcessInfo]:
        """Extract process information from the memory dump."""
        processes: List[ProcessInfo] = []
        try:
            for row in self._run_plugin(pslist.PsList):
                offset_key = next(
                    (key for key in row if key.startswith("Offset")),
                    None,
                )
                process = ProcessInfo(
                    pid=int(row.get("PID") or 0),
                    ppid=int(row.get("PPID") or 0),
                    name=str(row.get("ImageFileName") or "Unknown"),
                    offset=int(row.get(offset_key) or 0),
                    threads=int(row.get("Threads") or 0),
                    handles=int(row.get("Handles") or 0),
                    start_time=str(row.get("CreateTime") or "N/A"),
                    exit_time=str(row["ExitTime"]) if row.get("ExitTime") else None,
                )
                processes.append(process)
        except Exception as e:
            logging.error(f"Error getting process list: {e}")

        return processes

    async def get_network_connections(self) -> List[NetworkConnection]:
        """Extract network connection information from the memory dump."""
        connections: List[NetworkConnection] = []
        try:
            for row in self._run_plugin(netscan.NetScan):
                conn = NetworkConnection(
                    protocol=str(row.get("Proto") or "Unknown"),
                    local_addr=str(row.get("LocalAddr") or "N/A"),
                    local_port=int(row.get("LocalPort") or 0),
                    remote_addr=str(row.get("ForeignAddr") or "N/A"),
                    remote_port=int(row.get("ForeignPort") or 0),
                    state=str(row.get("State") or "N/A"),
                    pid=int(row["PID"]) if row.get("PID") is not None else None,
                    owner=str(row["Owner"]) if row.get("Owner") else None,
                )
                connections.append(conn)
        except Exception as e:
            logging.error(f"Error getting network connections: {e}")

        return connections

    async def get_services(self) -> List[ServiceInfo]:
        """Extract Windows service information."""
        services: List[ServiceInfo] = []
        try:
            for row in self._run_plugin(svcscan.SvcScan):
                service = ServiceInfo(
                    name=str(row.get("Name") or "Unknown"),
                    display_name=str(
                        row.get("Display") or row.get("Name") or "Unknown"
                    ),
                    type=str(row.get("Type") or "N/A"),
                    state=str(row.get("State") or "N/A"),
                    start=str(row.get("Start") or "N/A"),
                    pid=int(row["PID"]) if row.get("PID") is not None else None,
                    binary=str(
                        row.get("Binary") or row.get("Binary (Registry)") or "N/A"
                    ),
                    service_dll=str(row.get("Dll") or "N/A"),
                )
                services.append(service)
        except Exception as e:
            logging.error(f"Error getting services: {e}")
        return services

    async def get_dlls(self) -> Dict[int, List[DllInfo]]:
        """Extract loaded DLLs for each process."""
        dll_map: Dict[int, List[DllInfo]] = {}
        try:
            for row in self._run_plugin(dlllist.DllList):
                pid = int(row.get("PID") or 0)
                dll = DllInfo(
                    pid=pid,
                    base=int(row.get("Base") or 0),
                    size=int(row.get("Size") or 0),
                    name=str(row.get("Name") or "Unknown"),
                    path=str(row.get("Path") or "N/A"),
                )
                if pid not in dll_map:
                    dll_map[pid] = []
                dll_map[pid].append(dll)
        except Exception as e:
            logging.error(f"Error getting DLL list: {e}")
        return dll_map

    async def get_malfind(self) -> List[MalfindInfo]:
        """Scan for potentially malicious memory sections."""
        malfinds: List[MalfindInfo] = []
        try:
            for row in self._run_plugin(malfind.Malfind):
                start = int(row.get("Start VPN") or 0)
                end = int(row.get("End VPN") or start)
                malfind_info = MalfindInfo(
                    pid=int(row.get("PID") or 0),
                    start=start,
                    size=max(0, end - start),
                    protection=str(row.get("Protection") or "N/A"),
                    commit=str(row.get("CommitCharge") or "N/A"),
                    tag=str(row.get("Tag") or "N/A"),
                    notes=str(row["Notes"]) if row.get("Notes") else None,
                    hexdump=str(row.get("Hexdump") or "N/A"),
                )
                malfinds.append(malfind_info)
        except Exception as e:
            logging.error(f"Error scanning for malicious content: {e}")
        return malfinds

    async def get_registry_hives(self) -> List[RegistryHive]:
        """Extract registry hive information."""
        hives: List[RegistryHive] = []
        try:
            for row in self._run_plugin(hivelist.HiveList):
                full_path = str(row.get("FileFullPath") or "Unknown")
                hive = RegistryHive(
                    name=Path(full_path).name or full_path,
                    path=full_path,
                    offset=int(row.get("Offset") or 0),
                    file_output=str(row.get("File output") or "Disabled"),
                )
                hives.append(hive)
        except Exception as e:
            logging.error(f"Error getting registry hives: {e}")
        return hives

    async def get_command_lines(self) -> Dict[int, str]:
        """Extract command line information for processes."""
        cmdlines: Dict[int, str] = {}
        try:
            for row in self._run_plugin(cmdline.CmdLine):
                pid = int(row.get("PID") or 0)
                cmdline_str = str(row.get("Args") or "")
                cmdlines[pid] = cmdline_str
        except Exception as e:
            logging.error(f"Error getting command lines: {e}")

        return cmdlines

    def display_os_info(self, info_data: Dict[str, Any]) -> None:
        """Display OS information in a formatted table."""
        table = Table(title="Operating System Information")
        table.add_column("Property")
        table.add_column("Value")

        for key, value in info_data.items():
            if isinstance(value, (str, int, bool)):
                table.add_row(str(key), str(value))

        self.console.print(table)

    def display_processes(self, processes: List[ProcessInfo]) -> None:
        """Display process information in a formatted table."""
        table = Table(title="Running Processes")
        table.add_column("PID", justify="right")
        table.add_column("PPID", justify="right")
        table.add_column("Name")
        table.add_column("Threads", justify="right")
        table.add_column("Handles", justify="right")
        table.add_column("Start Time")
        table.add_column("Exit Time")

        for proc in sorted(processes, key=lambda x: x.pid):
            table.add_row(
                str(proc.pid),
                str(proc.ppid),
                proc.name,
                str(proc.threads),
                str(proc.handles),
                str(proc.start_time),
                str(proc.exit_time) if proc.exit_time else "Running",
            )

        self.console.print(table)

    def display_network_connections(self, connections: List[NetworkConnection]) -> None:
        """Display network connections in a formatted table."""
        table = Table(title="Network Connections")
        table.add_column("Protocol")
        table.add_column("Local Address")
        table.add_column("Remote Address")
        table.add_column("State")
        table.add_column("PID")
        table.add_column("Owner")

        for conn in connections:
            local = f"{conn.local_addr}:{conn.local_port}"
            remote = f"{conn.remote_addr}:{conn.remote_port}"

            table.add_row(
                conn.protocol,
                local,
                remote,
                conn.state,
                str(conn.pid) if conn.pid else "N/A",
                conn.owner if conn.owner else "N/A",
            )

        self.console.print(table)

    def display_services(self, services: List[ServiceInfo]) -> None:
        """Display Windows services in a formatted table."""
        table = Table(title="Windows Services")
        table.add_column("Name")
        table.add_column("Display Name")
        table.add_column("Type")
        table.add_column("State")
        table.add_column("Start")
        table.add_column("PID")
        table.add_column("Binary")
        table.add_column("Service DLL")

        for service in sorted(services, key=lambda x: x.name):
            table.add_row(
                service.name,
                service.display_name,
                service.type,
                service.state,
                service.start,
                str(service.pid) if service.pid else "N/A",
                service.binary or "N/A",
                service.service_dll or "N/A",
            )

        self.console.print(table)

    def display_dlls(self, dll_map: Dict[int, List[DllInfo]]) -> None:
        """Display loaded DLLs in a formatted table."""
        table = Table(title="Loaded DLLs by Process")
        table.add_column("PID", justify="right")
        table.add_column("DLL Name")
        table.add_column("Base Address", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Path")

        for pid, dlls in sorted(dll_map.items()):
            for dll in sorted(dlls, key=lambda x: x.name):
                table.add_row(
                    str(pid),
                    dll.name,
                    hex(dll.base),
                    str(dll.size),
                    dll.path,
                )

        self.console.print(table)

    def display_malfind(self, malfinds: List[MalfindInfo]) -> None:
        """Display potentially malicious memory sections."""
        if not malfinds:
            self.console.print("[green]No suspicious memory sections found[/green]")
            return

        table = Table(title="Suspicious Memory Sections (Malfind)")
        table.add_column("PID", justify="right")
        table.add_column("Start Address", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Protection")
        table.add_column("Commit")
        table.add_column("Tag")
        table.add_column("Notes")

        for mf in sorted(malfinds, key=lambda x: x.pid):
            table.add_row(
                str(mf.pid),
                hex(mf.start),
                str(mf.size),
                mf.protection,
                mf.commit,
                mf.tag,
                mf.notes or "N/A",
            )

            if mf.hexdump != "N/A":
                hex_table = Table(title=f"Hexdump for PID {mf.pid} at {hex(mf.start)}")
                hex_table.add_column("Hexdump")
                hex_table.add_row(mf.hexdump)
                self.console.print(hex_table)

        self.console.print(table)

    def display_registry_hives(self, hives: List[RegistryHive]) -> None:
        """Display registry hive information."""
        table = Table(title="Registry Hives")
        table.add_column("Hive Name")
        table.add_column("Path")
        table.add_column("Offset", justify="right")
        table.add_column("File Output")

        for hive in sorted(hives, key=lambda x: x.name):
            table.add_row(
                hive.name,
                hive.path,
                hex(hive.offset),
                hive.file_output or "N/A",
            )

        self.console.print(table)

    def display_command_lines(self, cmdlines: Dict[int, str]) -> None:
        """Display process command lines in a formatted table."""
        table = Table(title="Process Command Lines")
        table.add_column("PID", justify="right")
        table.add_column("Command Line")

        for pid, command_line in sorted(cmdlines.items()):
            table.add_row(str(pid), command_line or "N/A")

        self.console.print(table)

    def _demo_results(
        self,
    ) -> tuple[
        Dict[str, Any],
        List[ProcessInfo],
        List[NetworkConnection],
        Dict[int, str],
        List[ServiceInfo],
        Dict[int, List[DllInfo]],
        List[MalfindInfo],
        List[RegistryHive],
    ]:
        """Return sample data for demo mode."""
        os_info = {
            "Kernel Base": "0xf8003c000000",
            "DTB": "0x1aa000",
            "Symbols": "windows-10-x64-demo",
            "Is64Bit": True,
            "NtSystemRoot": r"C:\Windows",
            "NtMajorVersion": "10",
            "NtMinorVersion": "0",
            "SystemTime": "2026-03-13 22:45:00 UTC",
        }

        processes = [
            ProcessInfo(
                pid=4,
                ppid=0,
                name="System",
                offset=0x1F4A020,
                threads=152,
                handles=680,
                start_time="2026-03-13 21:58:11",
                exit_time=None,
            ),
            ProcessInfo(
                pid=612,
                ppid=4,
                name="services.exe",
                offset=0x20AB7C0,
                threads=12,
                handles=410,
                start_time="2026-03-13 21:58:24",
                exit_time=None,
            ),
            ProcessInfo(
                pid=3184,
                ppid=612,
                name="powershell.exe",
                offset=0x2C0B410,
                threads=9,
                handles=196,
                start_time="2026-03-13 22:11:08",
                exit_time=None,
            ),
        ]

        connections = [
            NetworkConnection(
                protocol="TCPv4",
                local_addr="192.168.1.10",
                local_port=49712,
                remote_addr="142.250.183.78",
                remote_port=443,
                state="ESTABLISHED",
                pid=3184,
                owner="powershell.exe",
            ),
            NetworkConnection(
                protocol="TCPv4",
                local_addr="0.0.0.0",
                local_port=135,
                remote_addr="0.0.0.0",
                remote_port=0,
                state="LISTENING",
                pid=612,
                owner="services.exe",
            ),
        ]

        cmdlines = {
            612: r"C:\Windows\System32\services.exe",
            3184: r"powershell.exe -ExecutionPolicy Bypass -File triage.ps1",
        }

        services = [
            ServiceInfo(
                name="WinDefend",
                display_name="Microsoft Defender Antivirus Service",
                type="SERVICE_WIN32_OWN_PROCESS",
                state="RUNNING",
                start="AUTO_START",
                pid=2516,
                binary=r"C:\Program Files\Windows Defender\MsMpEng.exe",
                service_dll="N/A",
            ),
            ServiceInfo(
                name="Schedule",
                display_name="Task Scheduler",
                type="SERVICE_WIN32_SHARE_PROCESS",
                state="RUNNING",
                start="AUTO_START",
                pid=612,
                binary=r"C:\Windows\System32\svchost.exe -k netsvcs -p",
                service_dll=r"C:\Windows\System32\schedsvc.dll",
            ),
        ]

        dlls = {
            3184: [
                DllInfo(
                    pid=3184,
                    base=0x7FFB30000000,
                    size=0x1C0000,
                    name="KERNEL32.DLL",
                    path=r"C:\Windows\System32\KERNEL32.DLL",
                ),
                DllInfo(
                    pid=3184,
                    base=0x7FFB2F000000,
                    size=0xB4000,
                    name="KERNELBASE.dll",
                    path=r"C:\Windows\System32\KERNELBASE.dll",
                ),
            ]
        }

        malfinds = [
            MalfindInfo(
                pid=3184,
                start=0x1A3F0000,
                size=0x2000,
                protection="PAGE_EXECUTE_READWRITE",
                commit="4",
                tag="VadS",
                notes="MZ header",
                hexdump=(
                    "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 MZ.............."
                ),
            )
        ]

        registry_hives = [
            RegistryHive(
                name="SYSTEM",
                path=r"\SystemRoot\System32\Config\SYSTEM",
                offset=0x9C7A1000,
                file_output="Disabled",
            ),
            RegistryHive(
                name="SOFTWARE",
                path=r"\SystemRoot\System32\Config\SOFTWARE",
                offset=0x9C8B4000,
                file_output="Disabled",
            ),
        ]

        return (
            os_info,
            processes,
            connections,
            cmdlines,
            services,
            dlls,
            malfinds,
            registry_hives,
        )

    async def analyze(self) -> None:
        """Perform the memory dump analysis."""
        if self.demo_mode:
            with Progress() as progress:
                tasks = [
                    progress.add_task("[cyan]Preparing Demo OS Information...", total=1),
                    progress.add_task("[cyan]Preparing Demo Processes...", total=1),
                    progress.add_task(
                        "[cyan]Preparing Demo Network Connections...", total=1
                    ),
                    progress.add_task("[cyan]Preparing Demo Command Lines...", total=1),
                    progress.add_task("[cyan]Preparing Demo Services...", total=1),
                    progress.add_task("[cyan]Preparing Demo DLLs...", total=1),
                    progress.add_task(
                        "[cyan]Preparing Demo Suspicious Memory Sections...", total=1
                    ),
                    progress.add_task("[cyan]Preparing Demo Registry Hives...", total=1),
                ]
                (
                    os_info,
                    processes,
                    connections,
                    cmdlines,
                    services,
                    dlls,
                    malfinds,
                    registry_hives,
                ) = self._demo_results()
                for task in tasks:
                    progress.update(task, advance=1)
        else:
            if not self.initialize_context():
                self.console.print("[red]Failed to initialize Volatility context[/red]")
                return

            with Progress() as progress:
                task1 = progress.add_task("[cyan]Analyzing OS Information...", total=1)
                task2 = progress.add_task("[cyan]Analyzing Processes...", total=1)
                task3 = progress.add_task(
                    "[cyan]Analyzing Network Connections...", total=1
                )
                task4 = progress.add_task(
                    "[cyan]Analyzing Command Lines...", total=1
                )

                os_info = await self.get_os_info()
                progress.update(task1, advance=1)

                processes = await self.get_processes()
                progress.update(task2, advance=1)

                connections = await self.get_network_connections()
                progress.update(task3, advance=1)

                cmdlines = await self.get_command_lines()
                progress.update(task4, advance=1)

                task5 = progress.add_task("[cyan]Analyzing Services...", total=1)
                services = await self.get_services()
                progress.update(task5, advance=1)

                task6 = progress.add_task("[cyan]Analyzing DLLs...", total=1)
                dlls = await self.get_dlls()
                progress.update(task6, advance=1)

                task7 = progress.add_task(
                    "[cyan]Scanning for Suspicious Memory Sections...", total=1
                )
                malfinds = await self.get_malfind()
                progress.update(task7, advance=1)

                task8 = progress.add_task(
                    "[cyan]Analyzing Registry Hives...", total=1
                )
                registry_hives = await self.get_registry_hives()
                progress.update(task8, advance=1)

        self.console.print("\n=== Memory Dump Analysis Results ===\n")

        if os_info:
            self.display_os_info(os_info)
            print("\n")

        if processes:
            self.display_processes(processes)
            print("\n")

        if connections:
            self.display_network_connections(connections)
            print("\n")

        if cmdlines:
            self.display_command_lines(cmdlines)
            print("\n")

        if services:
            self.display_services(services)
            print("\n")

        if dlls:
            self.display_dlls(dlls)
            print("\n")

        self.display_malfind(malfinds)
        print("\n")

        if registry_hives:
            self.display_registry_hives(registry_hives)


async def main() -> None:
    """Main function to run the memory dump analysis."""
    if len(sys.argv) != 2:
        print("Usage: python memory_forensics.py <path_to_memory_dump>")
        print("   or: python memory_forensics.py --demo")
        sys.exit(1)

    argument = sys.argv[1]
    if argument in {"--demo", "-d"}:
        analyzer = MemoryDumpAnalyzer(demo_mode=True)
    else:
        analyzer = MemoryDumpAnalyzer(argument)
    await analyzer.analyze()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
