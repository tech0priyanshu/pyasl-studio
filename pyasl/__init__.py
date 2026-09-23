from ._version import __version__

__all__ = [
    "load_data",
    "run_pipeline",
]


def __getattr__(name):
    if name == "load_data":
        from .utils.data_import import load_data

        return load_data
    if name == "run_pipeline":
        from .pipelines.run_pipeline import run_pipeline

        return run_pipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")