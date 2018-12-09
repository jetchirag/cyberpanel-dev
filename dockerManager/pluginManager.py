from signals import *
from plogical.pluginManagerGlobal import pluginManagerGlobal

class pluginManager:

    @staticmethod
    def preContainerCreation(request):
        return pluginManagerGlobal.globalPlug(request, preContainerCreation)

    @staticmethod
    def postContainerCreation(request, response):
        return pluginManagerGlobal.globalPlug(request, postContainerCreation, response)