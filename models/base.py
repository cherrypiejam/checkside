import abc

class Base(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def trace(path, env={}):
        pass

    @abc.abstractmethod
    def filter(traces, env={}):
        pass

    @abc.abstractmethod
    def analyse(traces, env={}):
        pass
