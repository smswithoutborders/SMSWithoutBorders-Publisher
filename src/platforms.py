#!/bin/python

import importlib

class Platforms:

    # TODO: this are created in a dir called platforms and would be parsed to get them
    currentPlatforms = {
            "google" : ["gmail"],
        }

    def __init__(self, platform):
        for providers in currentPlatforms:
            if not platform in currentPlatforms[providers]:
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
