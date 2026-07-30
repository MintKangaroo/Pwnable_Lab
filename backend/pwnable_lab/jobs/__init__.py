"""분석 작업 큐 추상화."""

from pwnable_lab.jobs.queue import AnalysisJobQueue, InlineAnalysisJobQueue

__all__ = ["AnalysisJobQueue", "InlineAnalysisJobQueue"]
