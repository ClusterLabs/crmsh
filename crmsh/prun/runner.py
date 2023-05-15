# runner.py - fork and exec multiple child processes concurrently
import asyncio
import fcntl
import os
import select
import typing


class Task:
    """holding the inputs and outputs of a command."""
    DevNull = 0
    Stdout = 1
    Capture = 2

    class RedirectToFile:
        def __init__(self, path):
            self.path = path

    def __init__(
            self,
            args: typing.Sequence[str],
            input: typing.Optional[bytes] = None,
            stdout: typing.Union[int, RedirectToFile] = DevNull,
            stderr: typing.Union[int, RedirectToFile] = DevNull,
            context=None,
    ):
        # Inputs
        self.args = args
        self.input = input
        self.stdout_config = stdout
        self.stderr_config = stderr
        # Results
        self.returncode: typing.Optional[int] = None
        self.stdout: typing.Optional[bytes] = None
        self.stderr: typing.Optional[bytes] = None
        # Caller can pass arbitrary data to context, it is kept untouched.
        self.context = context


class Runner:
    def __init__(self, concurrency):
        self._concurrency_limiter = asyncio.Semaphore(concurrency)
        self._tasks: typing.List[Task] = []

    def add_task(self, task: Task):
        self._tasks.append(task)

    def run(self, timeout_seconds: int = -1):
        awaitable = asyncio.gather(
            *[
                self._concurrency_limit(self._concurrency_limiter, self._run(task))
                for task in self._tasks
            ],
            return_exceptions=True,
        )
        if timeout_seconds > 0:
            awaitable = self._timeout_limit(timeout_seconds, awaitable)
        return asyncio.get_event_loop().run_until_complete(awaitable)

    async def _timeout_limit(self, timeout_seconds: int, awaitable: typing.Awaitable):
        assert timeout_seconds > 0
        try:
            return await asyncio.wait_for(awaitable, timeout_seconds)
        except asyncio.TimeoutError:
            return self._tasks

    @staticmethod
    async def _concurrency_limit(semaphore: asyncio.Semaphore, coroutine: typing.Coroutine):
        await semaphore.acquire()
        try:
            return await coroutine
        finally:
            semaphore.release()

    @staticmethod
    async def _run(task: Task):
        wait_stdout_writer = None
        if task.stdout_config == Task.DevNull:
            stdout = asyncio.subprocess.DEVNULL
        elif task.stdout_config == Task.Capture:
            stdout = asyncio.subprocess.PIPE
        elif isinstance(task.stdout_config, Task.RedirectToFile):
            stdout, wait_stdout_writer = FileIOWriter.create(task.stdout_config.path)
        else:
            assert False

        wait_stderr_writer = None
        if task.stderr_config == Task.DevNull:
            stderr = asyncio.subprocess.DEVNULL
        elif task.stderr_config == Task.Stdout:
            stderr = asyncio.subprocess.STDOUT
        elif task.stderr_config == Task.Capture:
            stderr = asyncio.subprocess.PIPE
        elif isinstance(task.stderr_config, Task.RedirectToFile):
            stderr, wait_stderr_writer = FileIOWriter.create(task.stderr_config.path)
        else:
            assert False

        try:
            try:
                child = await asyncio.create_subprocess_exec(
                    *task.args,
                    stdin=asyncio.subprocess.PIPE if task.input else asyncio.subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                )
            finally:
                # Closing the pipe inlet make the writer thread to exit.
                if isinstance(stdout, typing.BinaryIO):
                    stdout.close()
                if isinstance(stderr, typing.BinaryIO):
                    stderr.close()
            if wait_stdout_writer is not None:
                await wait_stdout_writer
            if wait_stderr_writer is not None:
                await wait_stderr_writer
            task.stdout, task.stderr = await child.communicate(task.input)
            task.returncode = child.returncode
        except asyncio.CancelledError:
            # Do not try to kill the child here. In a race condition, an unrelated process may be killed.
            # Whether the task is canceled can be identified with task.returncode. No need to reraise.
            pass
        return task


class FileIOWriter:
    # Disk I/O is blocking. To make it to work with non-blocking I/O, a thread is created to write the file.
    # The event loop thread send data needs to be written over a pipe to the thread.
    @staticmethod
    def _run(path: str, pipe_outlet_fd: int):
        fd = pipe_outlet_fd
        try:
            fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK | fcntl.fcntl(fd, fcntl.F_GETFL))
            polling = True
            poll = select.poll()
            poll.register(fd, select.POLLIN)
            with open(path, 'wb') as f:
                while polling:
                    for fd, events in poll.poll():
                        if events & select.POLLIN:
                            while True:
                                try:
                                    data = os.read(fd, 4096)
                                    if data:
                                        f.write(data)
                                    else:
                                        polling = False
                                        break
                                except BlockingIOError:
                                    break
        finally:
            os.close(fd)

    @staticmethod
    def create(path: str) -> typing.Tuple[typing.BinaryIO, typing.Coroutine]:
        """Create the pipe and the thread.
        Returns the inlet of the pipe and a coroutine can be await for the termination of the thread."""
        pipe_outlet, pipe_inlet = os.pipe2(os.O_CLOEXEC)
        wait_thread = asyncio.to_thread(FileIOWriter._run, path, pipe_outlet)
        return open(pipe_inlet, 'wb'), wait_thread
