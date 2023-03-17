import asyncio
import typing


class Task:
    def __init__(
            self,
            args: typing.Sequence[str],
            input: typing.Optional[bytes] = None,
            capture_stdout: bool = False,
            capture_stderr: bool = False,
            inline_stderr: bool = False,
            context=None,
    ):
        self.args = args
        self.input = input
        self.capture_stdout = capture_stdout
        self.capture_stderr = capture_stderr
        self.inline_stderr = inline_stderr
        self.returncode: typing.Optional[int] = None
        self.stdout: typing.Optional[bytes] = None
        self.stderr: typing.Optional[bytes] = None
        self.context = context


class Runner:
    def __init__(self):
        self._tasks: typing.List[Task] = []

    def add_task(self, task: Task):
        self._tasks.append(task)

    def run(self):
        return asyncio.get_event_loop().run_until_complete(
            asyncio.gather(*[self._run(task) for task in self._tasks], return_exceptions=True)
        )

    @staticmethod
    async def _run(task: Task):
        if task.inline_stderr:
            stderr = asyncio.subprocess.STDOUT
        elif task.capture_stderr:
            stderr = asyncio.subprocess.PIPE
        else:
            stderr = asyncio.subprocess.DEVNULL
        if task.capture_stdout or task.inline_stderr:
            stdout = asyncio.subprocess.PIPE
        else:
            stdout = asyncio.subprocess.DEVNULL
        child = await asyncio.create_subprocess_exec(
            *task.args,
            stdin=asyncio.subprocess.PIPE if task.input else asyncio.subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        task.stdout, task.stderr = await child.communicate(task.input)
        task.returncode = child.returncode
        return task
