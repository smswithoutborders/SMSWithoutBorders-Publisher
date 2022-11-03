#!/usr/bin/env python3

import importlib
import logging


print("Importing this guy!")

class Platforms:
    """
    - ENV variable has the location of the platforms 
    """

    def __init__(self, name: str, path_to_file: str):
        """
        import the lib here and use it
        """
        self.name = name
        self.path_to_file = path_to_file

        try:
            self.__import_platform__()
        except Exception as error:
            raise error


    def __import_platform__(self) -> None:
        """
        # https://docs.python.org/3/library/importlib.html#module-importlib.util
        """
        try:
            spec = importlib.util.spec_from_file_location(self.name, self.path_to_file)

            self.module = importlib.util.module_from_spec(spec)

            spec.loader.exec_module(module)

        except Exception as error:
            raise error


    @staticmethod
    def get_platform_from_letter(platform_letter: str):
        """
        TODO:
            - consume something from the BE Pub lib and use that to get the request going out
        """


    def publish(self, data: str) -> None:
        """
        - Dynamically import the lib, or import the lib at some other time.
        """
