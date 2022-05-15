#!/bin/python

import logging
import importlib
import importlib.util
import os

logging.basicConfig(level='DEBUG')
class Platforms:

    def __init__(self, platform_name: str = None):
        """
        """
        self.platforms_letters = {
                'g' : 'gmail',
                't' : 'twitter'
                }
        self.platforms_type = {
                'gmail':'email'
                }

        if platform_name and platform_name in self.platforms_type:
            self.platform_type = self.platforms_type[platform_name]


    @staticmethod
    def list() -> dict:
        platforms_path = os.path.join(os.path.dirname(__file__), 'available')
        platforms = {}

        for available_root, available_dirs, files in os.walk( platforms_path ):
            for available_dir in available_dirs:


                """
                Begins scanning independent platforms
                """
                for root, dirs, available_platform_files in os.walk( 
                        platforms_path + "/" + available_dir ):

                    for available_file in available_platform_files:

                        # logging.debug("available files: %s", available_file)
                        filename_no_extension = available_file.split('.')[:-1]
                        filename_no_extension = "".join(filename_no_extension)
                        # logging.debug("filaname no extension: %s", filename_no_extension)

                        if filename_no_extension == available_dir:

                            if len(platforms) < 1:
                                platforms[available_dir] = []

                            platforms_path = os.path.join(
                                    os.path.dirname(__file__), 
                                    f'available/{filename_no_extension}', available_file)

                            platforms[available_dir] = platforms_path

                            break

        return platforms


    def __import_available_platforms__(self, platforms: dict) -> dict:
        """
        """

        imported_platforms = {}
        for platform_name, platform_filepath in platforms.items():
            try:
                spec = importlib.util.spec_from_file_location(platform_name, platform_filepath)
                platform_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(platform_module)

                # logging.debug(dir(platform_module))
                imported_platforms[platform_name] = platform_module
            except Exception as error:
                logging.exception(error)


        return imported_platforms


    def get_platform(self, platform_letter: str) -> tuple:
        """
        """
        platform_name =  self.platforms_letters[platform_letter] 
        imported_platforms = self.__import_available_platforms__(Platforms.list())
        
        self.__init__(platform_name)

        return platform_name, self.platform_type, imported_platforms[platform_name]

    def execute(self, protocol, body, userDetails):
        try:
            # print(f">> Executing for platform: <{self.platform_name}:{protocol}:{body}:{userDetails}>")
            # print(f">> Executing for platform: <{self.platform_name}:{protocol}:{body}>")
            # print(f">> Executing for platform: <{self.platform_name}:{protocol}:{body}:{userDetails[self.provider]}>")
            results = self.platform.execute( protocol=protocol, body=body, userDetails=userDetails["user_token"][0])
            print("[+] Results:", results)
        except Exception as error:
            raise Exception(error)
        return results
