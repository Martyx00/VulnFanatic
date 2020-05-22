from binaryninja import *

# Helper methods for logical operations within the query language
def _and_(*args):
    tmp = []
    for arg in args:
        if arg.get_sources() == []:
            return Sources([])
        else:
            tmp += arg.get_sources()
    return Sources(tmp)

def _or_(*args):
    tmp = []
    for arg in args:
        tmp += arg.get_sources()
    return Sources(tmp)


class Sources:
    def __init__(self,sources):
        self.sources = sources
    
    def get_sources(self):
        return self.sources

    def get(self):
        return type(self)(self.sources.copy())
        
    def param(self,param_index):
        result = []
        for source in self.sources:
            if source["param"] == param_index:
                result.append(source)
        self.sources = result
        return self

    def params_from(self,param_index):
        result = []
        for source in self.sources:
            if source["param"] >= param_index:
                result.append(source)
        self.sources = result
        return self

    # Returns sources depending on whether the traced object contains source mentioned in source_type param
    def source_type(self,source_type):
        result = []
        for source in self.sources:
            if source_type in source["var_type"]:
                result.append(source)
        self.sources = result
        return self

    def not_constant(self):
        result = []
        for source in self.sources:
            if not "constant" in source["var_type"]:
                result.append(source)
        self.sources = result
        return self
    
    # Returns sources depending on whether the traced object contains function calls mentioned in function_calls param
    def function_calls(self,function_calls):
        result = []
        for source in self.sources:
            for fun_call in source["function_calls"]:
                for function in function_calls:
                    if function in fun_call["function_name"]:
                        result.append(source)
        self.sources = result
        return self

    def not_affected_by_function_calls(self,function_calls):
        result = []
        for source in self.sources:
            contains = False
            for function in function_calls:
                for fun_call in source["function_calls"]:
                    if function in fun_call["function_name"]:
                        contains = True
            if not contains:
                result.append(source)
        self.sources = result
        return self

    # Returns sources whether the traced object contains if_dependencies mentioned in if_deps param
    def if_dependencies(self,if_deps):
        result = []
        for source in self.sources:
            if source["if_dependencies"] == if_deps:
                result.append(source)
        self.sources = result
        return self

    # Returns sources where source and call are in the same branch
    def same_branch(self):
        result = []
        for source in self.sources:
            if source["same_branch"]:
                result.append(source)
        self.sources = result
        return self

    # Returns sources which are affected by the function with same branch dependence
    def same_branch_function_call(self,function):
        result = []
        for source in self.sources:
            for fun_call in source["function_calls"]:
                if function in fun_call["function_name"] and fun_call["same_branch"]:
                    result.append(source)
        self.sources = result
        return self


    # Check if source is marked as exported
    def exported(self):
        result = []
        for source in self.sources:
            if source["exported"]:
                result.append(source)
        self.sources = result
        return self

    # Checks if value of the source contains "val"
    def constant_contains(self,val):
        result = []
        for source in self.sources:
            if val in source["value"]:
                result.append(source)
        self.sources = result
        return self
        