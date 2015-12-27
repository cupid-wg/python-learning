from abc import ABC, ABCMeta, abstractmethod


class parentObj(ABC):

    @abstractmethod
    def print_a(self):
        pass

    @abstractmethod
    def print_b(self):
        pass


class childA(parentObj):

    def print_child_a(self):
        print("this is childA")

    def print_a(self):
        print("ChildA.print_a")

    def print_b(self):
        print("ChildA.print_b")


class childB(parentObj):

    def print_child_b(self):
        print("this is childB")

    def print_a(self):
        print("childB.print_a")

    def print_b(self):
        print("childB.print_b")


class childC(childA, childB):

    def print_b(self):
        return childB.print_b(self)

child_c = childC()
# should call childA function
child_c.print_child_a()
# should call childB function
child_c.print_child_b()
# should call childA function
child_c.print_a()
# should call childB function
child_c.print_b()
