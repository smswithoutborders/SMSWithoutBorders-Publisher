#!/bin/python

import logging
import importlib
import os

logging.basicConfig(level='DEBUG')
class Platforms:
    @staticmethod
    def list() -> dict:
        platforms_path = os.path.join(os.path.dirname(__file__), 'available')
        platforms = {}

        for root, available_dirs, files in os.walk( platforms_path ):
            for available_dir in available_dirs:


                """
                Begins scanning independent platforms
                """
                for root, dirs, available_platform_files in os.walk( platforms_path + "/" + available_dir ):
                    for available_file in available_platform_files:

                        # logging.debug("available files: %s", available_file)
                        filename_no_extension = available_file.split('.')[:-1]
                        filename_no_extension = "".join(filename_no_extension)
                        # logging.debug("filaname no extension: %s", filename_no_extension)

                        if filename_no_extension == available_dir:

                            if len(platforms) < 1:
                                platforms[available_dir] = []

                            logging.debug("available_file: %s", filename_no_extension)

                            platforms[available_dir].append(filename_no_extension)

                            break
        return platforms


    def import_available_platform(self, platform: str) -> None:
        """
        for provider in providers:
            def_platform = f"{provider}_{platform}"
            print("def_platform:", def_platform)

            if not def_platform in providers[provider]:
                # raise Exception("Unknown platform:", def_platform)
                continue
            else:
                platform_name = platform
                provider = provider

                # Being platform abstractions here
                importlib.invalidate_caches()
                
                LIB_NAME = f"{platforms_path}.{provider}".split('/')[-1:][0]
                LIB = f".{def_platform}"
                print(f"({LIB},{LIB_NAME})")
                platform = importlib.import_module(LIB, LIB_NAME)
        """

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
