from typing import Dict, List, Optional, Any
from pathlib import Path
import logging
import json
import sys
from datetime import datetime
from dataclasses import dataclass

import volatility3.plugins
from volatility3.cli import text_renderer
from volatility3.framework import contexts, automagic, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import (
    pslist, netscan, info, cmdline, filescan, registry, svcscan,
    dlllist, malfind, handles, modules, privileges, ldrmodules,
    sessions, vadinfo, virtmap, envars
)
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

@dataclass
class ServiceInfo:
    name: str
    display_name: str
    type: str
    state: str
    start: str
    pid: Optional[int]
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
    hexdump: str

@dataclass
class RegistryHive:
    hive: str
    path: str
    offset: int
    last_written: Optional[str]

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
    def __init__(self, dump_path: str) -> None:
        self.dump_path = Path(dump_path)
        self.console = Console()
        self.context: Optional[interfaces.context.ContextInterface] = None
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging for the analysis."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('memory_analysis.log'),
                logging.StreamHandler()
            ]
        )

    def initialize_context(self) -> bool:
        """Initialize Volatility context for the memory dump."""
        try:
            self.context = contexts.Context()
            self.context.config['automagic.LayerStacker.single_location'] = str(self.dump_path)

            automagics = automagic.available(self.context)
            automagic.choose_automagic(automagics, self.context)

            return True

        except Exception as e:
            logging.error(f"Failed to initialize Volatility context: {e}")
            return False

    async def get_os_info(self) -> Dict[str, Any]:
        """Retrieve operating system information from the memory dump."""
        try:
            plugin = info.Info(self.context, None)
            return await plugin.run()
        except Exception as e:
            logging.error(f"Error getting OS information: {e}")
            return {}

    async def get_processes(self) -> List[ProcessInfo]:
        """Extract process information from the memory dump."""
        processes: List[ProcessInfo] = []
        try:
            plugin = pslist.PsList(self.context, None)
            async for row in plugin.run():
                process = ProcessInfo(
                    pid=row[1],
                    ppid=row[2],
                    name=row[3],
                    offset=row[0],
                    threads=row[4],
                    handles=row[5],
                    start_time=row[6],
                    exit_time=row[7] if row[7] else None
                )
                processes.append(process)
        except Exception as e:
            logging.error(f"Error getting process list: {e}")

        return processes

    async def get_network_connections(self) -> List[NetworkConnection]:
        """Extract network connection information from the memory dump."""
        connections: List[NetworkConnection] = []
        try:
            plugin = netscan.NetScan(self.context, None)
            async for row in plugin.run():
                conn = NetworkConnection(
                    protocol=row[0],
                    local_addr=row[1],
                    local_port=row[2],
                    remote_addr=row[3],
                    remote_port=row[4],
                    state=row[5],
                    pid=row[6],
                    owner=row[7]
                )
                connections.append(conn)
        except Exception as e:
            logging.error(f"Error getting network connections: {e}")

        return connections

    async def get_services(self) -> List[ServiceInfo]:
        """Extract Windows service information."""
        services: List[ServiceInfo] = []
        try:
            plugin = svcscan.SvcScan(self.context, None)
            async for row in plugin.run():
                service = ServiceInfo(
                    name=row[0],
                    display_name=row[1],
                    type=row[2],
                    state=row[3],
                    start=row[4],
                    pid=row[5],
                    service_dll=row[6] if len(row) > 6 else None
                )
                services.append(service)
        except Exception as e:
            logging.error(f"Error getting services: {e}")
        return services

    async def get_dlls(self) -> Dict[int, List[DllInfo]]:
        """Extract loaded DLLs for each process."""
        dll_map: Dict[int, List[DllInfo]] = {}
        try:
            plugin = dlllist.DllList(self.context, None)
            async for row in plugin.run():
                pid = row[0]
                dll = DllInfo(
                    pid=pid,
                    base=row[1],
                    size=row[2],
                    name=row[3],
                    path=row[4]
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
            plugin = malfind.Malfind(self.context, None)
            async for row in plugin.run():
                malfind_info = MalfindInfo(
                    pid=row[0],
                    start=row[1],
                    size=row[2],
                    protection=row[3],
                    commit=row[4],
                    tag=row[5],
                    hexdump=row[6] if len(row) > 6 else "N/A"
                )
                malfinds.append(malfind_info)
        except Exception as e:
            logging.error(f"Error scanning for malicious content: {e}")
        return malfinds

    async def get_registry_hives(self) -> List[RegistryHive]:
        """Extract registry hive information."""
        hives: List[RegistryHive] = []
        try:
            plugin = registry.HiveList(self.context, None)
            async for row in plugin.run():
                hive = RegistryHive(
                    hive=row[0],
                    path=row[1],
                    offset=row[2],
                    last_written=row[3] if len(row) > 3 else None
                )
                hives.append(hive)
        except Exception as e:
            logging.error(f"Error getting registry hives: {e}")
        return hives

    async def get_command_lines(self) -> Dict[int, str]:
        """Extract command line information for processes."""
        cmdlines: Dict[int, str] = {}
        try:
            plugin = cmdline.CmdLine(self.context, None)
            async for row in plugin.run():
                pid = row[0]
                cmdline_str = row[1]
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
            if isinstance(value, (str, int)):
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
                str(proc.exit_time) if proc.exit_time else "Running"
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
                conn.owner if conn.owner else "N/A"
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
        table.add_column("Service DLL")

        for service in sorted(services, key=lambda x: x.name):
            table.add_row(
                service.name,
                service.display_name,
                service.type,
                service.state,
                service.start,
                str(service.pid) if service.pid else "N/A",
                service.service_dll or "N/A"
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
                    dll.path
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

        for mf in sorted(malfinds, key=lambda x: x.pid):
            table.add_row(
                str(mf.pid),
                hex(mf.start),
                str(mf.size),
                mf.protection,
                mf.commit,
                mf.tag
            )

            # Print hexdump in a separate table if available
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
        table.add_column("Last Written")

        for hive in sorted(hives, key=lambda x: x.hive):
            table.add_row(
                hive.hive,
                hive.path,
                hex(hive.offset),
                str(hive.last_written) if hive.last_written else "N/A"
            )

        self.console.print(table)

    def display_command_lines(self, cmdlines: Dict[int, str]) -> None:
        """Display process command lines in a formatted table."""
        table = Table(title="Process Command Lines")
        table.add_column("PID", justify="right")
        table.add_column("Command Line")

        for pid, cmdline in sorted(cmdlines.items()):
            table.add_row(str(pid), cmdline)

        self.console.print(table)

    async def analyze(self) -> None:
        """Perform the memory dump analysis."""
        if not self.initialize_context():
            self.console.print("[red]Failed to initialize Volatility context[/red]")
            return

        with Progress() as progress:
            task1 = progress.add_task("[cyan]Analyzing OS Information...", total=1)
            task2 = progress.add_task("[cyan]Analyzing Processes...", total=1)
            task3 = progress.add_task("[cyan]Analyzing Network Connections...", total=1)
            task4 = progress.add_task("[cyan]Analyzing Command Lines...", total=1)

            # Gather information
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

            task7 = progress.add_task("[cyan]Scanning for Suspicious Memory Sections...", total=1)
            malfinds = await self.get_malfind()
            progress.update(task7, advance=1)

            task8 = progress.add_task("[cyan]Analyzing Registry Hives...", total=1)
            registry_hives = await self.get_registry_hives()
            progress.update(task8, advance=1)

        # Display information
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

        self.display_malfind(malfinds)  # Always display malfind results
        print("\n")

        if registry_hives:
            self.display_registry_hives(registry_hives)

async def main() -> None:
    """Main function to run the memory dump analysis."""
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_memory_dump>")
        sys.exit(1)

    dump_path = sys.argv[1]
    analyzer = MemoryDumpAnalyzer(dump_path)
    await analyzer.analyze()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
