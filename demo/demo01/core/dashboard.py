from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    MofNCompleteColumn
)
from rich.console import Console


class SecurityDashboard:
    def __init__(self):
        self.console = Console()
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            refresh_per_second = 10
        )

    def add_task(self, description, total=100) -> int:
        """添加新任务并返回任务ID"""
        return self.progress.add_task(
            description=f"[cyan]• {description}",
            total=total
        )

    def update(self, task_id, advance=1, **kwargs):
        """更新指定任务的进度"""
        self.progress.update(task_id, advance=advance, **kwargs)

    def start(self):
        """进入实时刷新模式"""
        self.progress.start()

    def stop(self):
        """停止所有进度跟踪"""
        self.progress.stop()

