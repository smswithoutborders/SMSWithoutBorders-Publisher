#!/bin/python

import importlib
import os

class Platforms:

    # TODO: this are created in a dir called platforms and would be parsed to get them
    def __init__(self, platform):
        self.DEFAULT_PROVIDERS_PATH = "platforms/"
        # scan for all submodules
        providers = {}
        for root, dirs, files in os.walk( self.DEFAULT_PROVIDERS_PATH ):
            for _dir in dirs:
                providers[_dir] = []
                for root, dirs, files in os.walk( self.DEFAULT_PROVIDERS_PATH + _dir ):
                    for _file in files:
                        if _file.split('.')[0] == _dir:
                            providers[_dir].append( _file )
                    break
                
            break
        print( providers )

        for provider in providers:
            if not platform in providers[provider]:
                raise Exception(f"Unknown platform: {platform}")
            else:
                self.platform_name = platform

                # Being platform abstractions here
                importlib.invalidate_caches()
                self.platform = importlib.import_module(platform)

    def execute(self, protocol, body, userDetails):
        try:
            print(">> Executing for platform: <{self.platform_name}:{protocol}>")
            results = self.platform.execute( protocol=protocol, body=body, userDetails=userDetails )
        except Exception as error:
            raise Exception(error)
        return results
