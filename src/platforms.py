#!/bin/python

import importlib
import os

class Platforms:

    # TODO: this are created in a dir called platforms and would be parsed to get them
    def __init__(self, platform):
        self.DEFAULT_PROVIDERS_PATH = "Platforms"
        # scan for all submodules
        providers = {}
        for root, dirs, files in os.walk( self.DEFAULT_PROVIDERS_PATH ):
            for _dir in dirs:
                providers[_dir] = []
                for root, dirs, files in os.walk( self.DEFAULT_PROVIDERS_PATH+"/"+_dir ):
                    # print(f"Files: {files}")
                    for _file in files:
                        if _file.split('_')[0] == _dir:
                            splitted_filename = _file.split('.')[:-1]
                            merged_filename = '_'.join(splitted_filename)
                            # print("MF:>>", merged_filename)
                            providers[_dir].append(merged_filename)
                            break
                    break
            break
        # print( providers )

        for provider in providers:
            def_platform = f"{provider}_{platform}"
            # print("def_platform:", def_platform)

            if not def_platform in providers[provider]:
                raise Exception("Unknown platform:", def_platform)
            else:
                self.platform_name = platform
                self.provider = provider

                # Being platform abstractions here
                importlib.invalidate_caches()
                
                LIB_NAME = f"{self.DEFAULT_PROVIDERS_PATH}.{provider}"
                LIB = f".{def_platform}"
                # print(f"({LIB},{LIB_NAME})")
                self.platform = importlib.import_module(LIB, LIB_NAME)

    def execute(self, protocol, body, userDetails):
        try:
            print(f">> Executing for platform: <{self.platform_name}:{protocol}>")
            results = self.platform.execute( protocol=protocol, body=body, userDetails=userDetails[self.provider] )
        except Exception as error:
            raise Exception(error)
        return results
