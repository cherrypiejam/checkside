import abc

class BaseModel(metaclass=abc.ABCMeta):
    @staticmethod
    @abc.abstractmethod
    def trace(path, env={}):
        pass

    @staticmethod
    @abc.abstractmethod
    def filter(traces, env={}):
        pass

    @staticmethod
    @abc.abstractmethod
    def analyse(traces, env={}):
        pass
