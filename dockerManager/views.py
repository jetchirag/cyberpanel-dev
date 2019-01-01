# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render,redirect
from loginSystem.models import Administrator
from loginSystem.views import loadLoginPage
import docker
from django.http import HttpResponse
import json
import requests
from plogical.container import ContainerManager
from websiteFunctions.pluginManager import pluginManager

# Use default socket to connect
client = docker.from_env()

# Create your views here.
# Todo: Add json response for post requests instead redirects
def loadDockerHome(request):
    try:
        val = request.session['userID']
        admin = Administrator.objects.get(pk=val)
        return render(request,'dockerManager/index.html',{"type":admin.type})
    except KeyError:
        return redirect(loadLoginPage)      
      
def loadImages(request):
    try:
        val = request.session['userID']
        admin = Administrator.objects.get(pk=val)        
        return render(request,'dockerManager/images.html',{"type":admin.type})
    except KeyError:
        return redirect(loadLoginPage)     
    
def installImage(request):
    try:
        userID = request.session['userID']

        result = pluginManager.preWebsiteCreation(request) # Later change to preInstallInstallation

        if  result != 200:
            return result

        cm = ContainerManager()
        coreResult = cm.submitInstallImage(userID, json.loads(request.body))

        result = pluginManager.postWebsiteCreation(request, coreResult)
        if result != 200:
            return result

        return coreResult

    except KeyError:
        return redirect(loadLoginPage)
    

def viewContainer(request, name):
    try:

        if not request.GET._mutable:
            request.GET._mutable = True
        request.GET['name'] = name

        userID = request.session['userID']
        cm = ContainerManager(name)
        coreResult = cm.loadContainerHome(request, userID)

        return coreResult

    except KeyError:
        return redirect(loadLoginPage)    
            
def getTags(request):
    image = request.GET.get('image')
    page = request.GET.get('page')
    
    if ":" in image:
        image2 = image.split(":")[0] + "/" + image.split(":")[1]
    else:
        image2 = "library/" + image
        
    print image
    registryData = requests.get('https://registry.hub.docker.com/v2/repositories/'+image2+'/tags', {'page':page}).json()
    
    tagList = []
    availableTags = []
    for image in client.images.list(image):
        for tag in image.tags:
            tagList.append(tag.split(":")[1] + " (available)") # So available tags comes on top
    try:
        for tag in registryData['results']:
            if tag['name'] not in availableTags:
                tagList.append(tag['name'])
        
        
        return HttpResponse(json.dumps(tagList), content_type="application/json")
    except:
        return HttpResponse(json.dumps([]),
        content_type="application/json")
    
def delContainer(request): 
    try:
        userID = request.session['userID']

        cm = ContainerManager()
        coreResult = cm.submitContainerDeletion(userID, json.loads(request.body))

        return coreResult

    except KeyError:
        return redirect(loadLoginPage)
    
    
def recreateContainer(request): 
    try:
        userID = request.session['userID']

        cm = ContainerManager()
        coreResult = cm.recreateContainer(userID, json.loads(request.body))

        return coreResult

    except KeyError:
        return redirect(loadLoginPage)    
    
def runContainer(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        return cm.createContainer(request, userID)
    except KeyError:
        return redirect(loadLoginPage)    
      
def listContainers(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        return cm.listContainers(request, userID)
    except KeyError:
        return redirect(loadLoginPage)
        
def getContainerLogs(request):
    try:
        userID = request.session['userID']

        cm = ContainerManager()
        coreResult = cm.getContainerLogs(userID, json.loads(request.body))
        return coreResult

    except KeyError:
        return redirect(loadLoginPage)    

def submitContainerCreation(request):
    try:
        userID = request.session['userID']

        result = pluginManager.preWebsiteCreation(request)

        if  result != 200:
            return result

        cm = ContainerManager()
        coreResult = cm.submitContainerCreation(userID, json.loads(request.body))

        result = pluginManager.postWebsiteCreation(request, coreResult)
        if result != 200:
            return result

        return coreResult

    except KeyError:
        return redirect(loadLoginPage)
    
def getContainerList(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        return cm.getContainerList(userID, json.loads(request.body))
    except KeyError:
        return redirect(loadLoginPage)
    
def doContainerAction(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.doContainerAction(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)
    
def getContainerStatus(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.getContainerStatus(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)    
    
def exportContainer(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.exportContainer(request, userID)
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)    
        
        
def saveContainerSettings(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.saveContainerSettings(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage) 
    
    
def getContainerTop(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.getContainerTop(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)

def dockerSettings(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.dockerSettings(request, userID)
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)
    
def assignContainer(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.assignContainer(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)
    
def searchImage(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.searchImage(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)
    
def manageImages(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.manageImages(request, userID)
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)
    
def getImageHistory(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.getImageHistory(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)
    
def removeImage(request):
    try:
        userID = request.session['userID']
        cm = ContainerManager()
        coreResult = cm.removeImage(userID, json.loads(request.body))
        
        return coreResult
    except KeyError:
        return redirect(loadLoginPage)    