#!/usr/local/CyberCP/bin/python2
from __future__ import division
import os
import os.path
import sys
import django
import mimetypes
sys.path.append('/usr/local/CyberCP')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "CyberCP.settings")
django.setup()
import json
from acl import ACLManager
import CyberCPLogFileWriter as logging
from django.shortcuts import HttpResponse, render
from loginSystem.models import Administrator, ACL
import subprocess
import shlex
import time
from dockerManager.models import Containers
from loginSystem.models import Administrator
from django.http import StreamingHttpResponse
from wsgiref.util import FileWrapper
import docker
import docker.utils
import requests

# Use default socket to connect
client = docker.from_env()
dockerAPI = docker.APIClient()

# Todo: Add check if docker is available/running

class ContainerManager:
    def __init__(self, name = None):
        self.name = name
        
    def createContainer(self, request = None, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'createContainer') == 0:
                return ACLManager.loadError()
            
            adminNames = ACLManager.loadAllUsers(userID)
            tag = request.GET.get('tag')
            image = request.GET.get('image')
#             Todo: Add check if url is correct i.e. query exists
            print "name:" + tag
            tag = tag.split(" (")[0]
            
            if "/" in image:
                name = image.split("/")[0] + "." + image.split("/")[0]
            else:
                name = image
            
            try:
                inspectImage =  dockerAPI.inspect_image(image+":"+tag)
            except docker.errors.ImageNotFound:
                val = request.session['userID']
                admin = Administrator.objects.get(pk=val)
                return render(request,'dockerManager/images.html',{"type":admin.type,
                                                                  'image':image,
                                                                   'tag':tag})                
                
            envList = {};
            if 'Env' in inspectImage['Config']:
                for item in inspectImage['Config']['Env']:
                    if '=' in item:
                        splitedItem = item.split('=',1)
                        print splitedItem
                        envList[splitedItem[0]] = splitedItem[1]
                    else:
                        envList[item] = ""
                        
            portConfig = {};
            if 'ExposedPorts' in inspectImage['Config']:
                for item in inspectImage['Config']['ExposedPorts']:
                    portDef = item.split('/')
                    portConfig[portDef[0]] = portDef[1]                
            
            print portConfig
            if image is None or image is '' or tag is None or tag is '':
                return redirect(loadImages)
            
            Data = {"ownerList": adminNames, "image":image, "name":name, "tag":tag, "portConfig": portConfig, "envList":envList}
        
            return render(request, 'dockerManager/runContainer.html', Data)

        except BaseException, msg:
            return HttpResponse(str(msg))
        
    def loadContainerHome(self, request = None, userID = None, data = None):
        
        name = self.name
        try:
            container = client.containers.get(name)
        except docker.errors.NotFound as err:
            return HttpResponse("Container not found")
        
        data = {}
        con = Containers.objects.get(name=name)
        data['name'] = name
        data['image'] = con.image + ":" + con.tag
        data['ports'] = json.loads(con.ports)
        data['cid'] = con.cid
        data['envList'] = json.loads(con.env)
        print data['envList']
        
        stats = container.stats(decode=False, stream=False)
        logs = container.logs(stream=True)
        
        data['status'] = container.status
        data['memoryLimit'] = con.memory
        if con.startOnReboot == 1:
            data['startOnReboot'] = 'true'
            data['restartPolicy'] = "Yes"
        else:
            data['startOnReboot'] = 'false'
            data['restartPolicy'] = "No"
        
        if 'usage' in stats['memory_stats']:
            # Calculate Usage 
            # Source: https://github.com/docker/docker/blob/28a7577a029780e4533faf3d057ec9f6c7a10948/api/client/stats.go#L309
            data['memoryUsage'] = (stats['memory_stats']['usage'] / stats['memory_stats']['limit']) * 100
            
            cpu_count = len(stats["cpu_stats"]["cpu_usage"]["percpu_usage"])
            data['cpuUsage'] = 0.0
            cpu_delta = float(stats["cpu_stats"]["cpu_usage"]["total_usage"]) - \
                        float(stats["precpu_stats"]["cpu_usage"]["total_usage"])
            system_delta = float(stats["cpu_stats"]["system_cpu_usage"]) - \
                           float(stats["precpu_stats"]["system_cpu_usage"])
            if system_delta > 0.0:
                data['cpuUsage'] = round(cpu_delta / system_delta * 100.0 * cpu_count, 3)
        else:
            data['memoryUsage'] = 0
            data['cpuUsage'] = 0;
            
        return render(request, 'dockerManager/viewContainer.html', data)
        
    def listContainers(self, request = None, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            containers = ACLManager.findAllContainers(currentACL, userID)
            
            allContainers = client.containers.list()
            containersList = []
            showUnlistedContainer = True
            
            # TODO: Add condition to show unlisted Containers only if user has admin level access

            unlistedContainers = []
            for container in allContainers:
                if container.name not in containers:
                    unlistedContainers.append(container)
                
            if not unlistedContainers:
                showUnlistedContainer = False
            
            adminNames = ACLManager.loadAllUsers(userID)
            
            pages = float(len(containers)) / float(10)
            pagination = []

            if pages <= 1.0:
                pages = 1
                pagination.append('<li><a href="\#"></a></li>')
            else:
                pages = ceil(pages)
                finalPages = int(pages) + 1

                for i in range(1, finalPages):
                    pagination.append('<li><a href="\#">' + str(i) + '</a></li>')

            return render(request, 'dockerManager/listContainers.html', {"pagination": pagination,
                                                                        "unlistedContainers": unlistedContainers,
                                                                        "adminNames": adminNames,
                                                                        "showUnlistedContainer":showUnlistedContainer})
        except BaseException, msg:
            return HttpResponse(str(msg))

    def getContainerLogs(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'createWebsite') == 0:
                return ACLManager.loadErrorJson('createWebSiteStatus', 0)

            name = data['name']
            
            container = client.containers.get(name)
            logs = container.logs()

            data_ret = {'containerLogStatus': 1, 'containerLog': logs, 'error_message': "None"}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)


        except BaseException, msg:
            data_ret = {'containerLogStatus': 0, 'containerLog':'Error', 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)
    
    def submitContainerCreation(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'createWebsite') == 0:
                return ACLManager.loadErrorJson('createWebSiteStatus', 0)

            name = data['name']
            image = data['image']
            tag = data['tag']
            websiteOwner = data['websiteOwner']
            memory = data['memory']
            envList = data['envList']
            
            inspectImage =  dockerAPI.inspect_image(image+":"+tag)
            portConfig = {}
            
            # Formatting envList for usage
            envDict = {}
            for key, value in envList.iteritems():
                # Todo: Add proper filters and checks for each variable 
                if (value['name'] != '') or (value['value'] != ''):
                    envDict[value['name']] = value['value']
            print envDict
            
            if 'ExposedPorts' in inspectImage['Config']:
                for item in inspectImage['Config']['ExposedPorts']:
                    # Do not allow priviledged port numbers
                    if int(data[item]) < 1024 or int(data[item]) > 65535:
                        data_ret = {'createContainerStatus': 0, 'error_message': "Choose port between 1024 and 65535"}
                        json_data = json.dumps(data_ret)
                        return HttpResponse(json_data)
                    portConfig[item] = data[item]
            
            ## Create Configurations
            
            admin = Administrator.objects.get(userName=websiteOwner)
            
            containerArgs = {'image':image+":"+tag,
                            'detach':True,
                            'name':name,
                            'ports':portConfig,
                            'environment':envDict}
            
            containerArgs['mem_limit'] = memory * 1048576; # Converts MB to bytes ( 0 * x = 0 for unlimited memory)

            container = client.containers.run(**containerArgs)
            
            con = Containers(admin=admin,
                            name=name,
                            tag=tag,
                            image=image,
                            memory=memory,
                            ports=json.dumps(portConfig),
                            env=json.dumps(envDict),
                            cid=container.id)
            
            con.save()

            data_ret = {'createContainerStatus': 1, 'error_message': "None"}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)


        except BaseException, msg:
            data_ret = {'createContainerStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)
        
    def submitInstallImage(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'createWebsite') == 0:
                return ACLManager.loadErrorJson('createWebSiteStatus', 0)

            image = data['image']
            tag = data['tag']
            
            print "Installing Image: " + image
            
            try:
                inspectImage =  dockerAPI.inspect_image(image+":"+tag)
                data_ret = {'installImageStatus': 0, 'error_message': "Image already installed"}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except docker.errors.ImageNotFound:
                pass
            
            try:
                image = client.images.pull(image, tag=tag)
                print image.id
            except docker.errors.APIError as msg:
                data_ret = {'installImageStatus': 0, 'error_message': str(msg)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)    
                
            
            data_ret = {'installImageStatus': 1, 'error_message': "None"}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)


        except BaseException, msg:
            data_ret = {'installImageStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)      
        
    def submitContainerDeletion(self, userID = None, data = None, called = False):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                if called:
                    return 'Permission error'
                else:
                    return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            name = data['name']
            unlisted = data['unlisted']
            print unlisted

            if not unlisted:
                containerOBJ = Containers.objects.get(name=name)
            
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                if called:
                    return 'Container does not exist'
                else:
                    data_ret = {'delContainerStatus': 0, 'error_message': 'Container does not exist'}
                    json_data = json.dumps(data_ret)
                    return HttpResponse(json_data)                
            
            try:
                container.stop() # Stop container
                container.kill() # INCASE graceful stop doesn't work
            except:
                pass
                        
            try:
                container.remove() # Finally remove container                    
            except docker.errors.APIError as err:
                data_ret = {'delContainerStatus': 0, 'error_message': str(err)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)                
            except:
                if called:
                    return "Unknown"
                else:
                    data_ret = {'delContainerStatus': 0, 'error_message': 'Unknown error'}
                    json_data = json.dumps(data_ret)
                    return HttpResponse(json_data)
                
            if not unlisted and not called:
                containerOBJ.delete()            
                
            if called:
                return 0
            else:
                data_ret = {'delContainerStatus': 1, 'error_message': "None"}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)

        except BaseException, msg:
            if called:
                return str(msg)
            else:
                data_ret = {'delContainerStatus': 0, 'error_message': str(msg)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)

    def getContainerList(self, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            pageNumber = int(data['page'])
            json_data = self.findContainersJson(currentACL, userID, pageNumber)
            final_dic = {'listContainerStatus': 1, 'error_message': "None", "data": json_data}
            final_json = json.dumps(final_dic)
            return HttpResponse(final_json)
        except BaseException, msg:
            dic = {'listContainerStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(dic)
            return HttpResponse(json_data)        
        
    def findContainersJson(self, currentACL, userID, pageNumber):
        finalPageNumber = ((pageNumber * 10)) - 10
        endPageNumber = finalPageNumber + 10
        containers = ACLManager.findContainersObjects(currentACL, userID)[finalPageNumber:endPageNumber]

        json_data = "["
        checker = 0

        try:
            ipFile = "/etc/cyberpanel/machineIP"
            f = open(ipFile)
            ipData = f.read()
            ipAddress = ipData.split('\n', 1)[0]
        except BaseException, msg:
            logging.CyberCPLogFileWriter.writeToFile("Failed to read machine IP, error:" + str(msg))
            ipAddress = "192.168.100.1"

        for items in containers:
            dic = {'name': items.name,'admin': items.admin.userName, 'tag':items.tag, 'image':items.image}

            if checker == 0:
                json_data = json_data + json.dumps(dic)
                checker = 1
            else:
                json_data = json_data + ',' + json.dumps(dic)

        json_data = json_data + ']'

        return json_data
    
    def doContainerAction(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            name = data['name']
            action = data['action']
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                data_ret = {'containerActionStatus': 0, 'error_message': 'Container does not exist'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'containerActionStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
            try:
                if action == 'start':
                    container.start()
                elif action == 'stop':
                    container.stop()
                elif action == 'restart':
                    container.restart()
                else:
                    data_ret = {'containerActionStatus': 0, 'error_message': 'Unknown Action'}
                    json_data = json.dumps(data_ret)
                    return HttpResponse(json_data)
            except docker.errors.APIError as err:
                data_ret = {'containerActionStatus': 0, 'error_message': str(err)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)

            time.sleep(3) # Wait 3 seconds for container to finish starting/stopping/restarting
            status = container.status
            data_ret = {'containerActionStatus': 1, 'error_message': 'None', 'status': status}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'containerActionStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

    def getContainerStatus(self, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            name = data['name']
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                data_ret = {'containerStatus': 0, 'error_message': 'Container does not exist'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'containerStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
            status = container.status
            data_ret = {'containerStatus': 1, 'error_message': 'None', 'status': status}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'containerStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)                
        
    def exportContainer(self, request = None, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)
            
            name = request.GET.get('name')
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                data_ret = {'containerStatus': 0, 'error_message': 'Container does not exist'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'containerStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
            eFile = container.export() # Export with default chunk size
            response =  HttpResponse(eFile, content_type='application/force-download')
            response['Content-Disposition'] = 'attachment; filename="'+ name +'.tar"'
            return response

        except BaseException, msg:
            data_ret = {'containerStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)  
                        
    def getContainerTop(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            name = data['name']
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                data_ret = {'containerTopStatus': 0, 'error_message': 'Container does not exist'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'containerTopStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
            try:
                top = container.top()
            except docker.errors.APIError as err:
                data_ret = {'containerTopStatus': 0, 'error_message': str(err)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)    

            data_ret = {'containerTopStatus': 1, 'error_message': 'None', 'processes':top}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'containerTopStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data) 
    
    def assignContainer(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'assignContainer') == 0:
                return ACLManager.loadErrorJson('assignContainerStatus', 0)

            name = data['name']
            websiteOwner = data['admin']
                
            admin = Administrator.objects.get(userName=websiteOwner)
            
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                data_ret = {'assignContainerStatus': 0, 'error_message': 'Container does not exist'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'assignContainerStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
            con = Containers(admin=admin,
                            name=name,
                            cid=container.id)
            
            con.save()
            
            data_ret = {'assignContainerStatus': 1, 'error_message': 'None'}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'assignContainerStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data) 
    
    def dockerSettings(self, request = None, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'createContainer') == 0:
                return ACLManager.loadError()

            adminNames = ACLManager.loadAllUsers(userID)
            
            Data = {}
        
            return render(request, 'dockerManager/dockerSettings.html', Data)

        except BaseException, msg:
            return HttpResponse(str(msg))
                
    def searchImage(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            string = data['string']
            try:
                matches = client.images.search(term=string)
            except docker.errors.APIError as err:
                data_ret = {'searchImageStatus': 0, 'error_message': str(err)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'searchImageStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
            print json.dumps(matches)
            
            for image in matches:
                if "/" in image['name']:
                    image['name2'] = image['name'].split("/")[0] + ":" + image['name'].split("/")[1]
                else:
                    image['name2'] = image['name']
                    
            
            data_ret = {'searchImageStatus': 1, 'error_message': 'None', 'matches':matches}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'searchImageStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)             
        
        
    def manageImages(self, request = None, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            containers = ACLManager.findAllContainers(currentACL, userID)
                        
            try:
                imageList = client.images.list()
            except docker.errors.APIError as err:
                return HttpResponse(str(err))
            
            images = {}
            names = []
            
            for image in imageList:
                name = image.attrs['RepoTags'][0].split(":")[0]
                if name in names:
                    images[name]['tags'].extend(image.tags)
                else:
                    names.append(name)
                    tags = []
                    images[name] = {"name":name,
                                  "tags":image.tags}
            print images
            return render(request, 'dockerManager/manageImages.html', {"images":images})
            
        except BaseException, msg:
            return HttpResponse(str(msg))
        
    def getImageHistory(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            name = data['name']
            try:
                image = client.images.get(name)
            except docker.errors.APIError as err:
                data_ret = {'imageHistoryStatus': 0, 'error_message': str(err)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'imageHistoryStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
                                
            
            data_ret = {'imageHistoryStatus': 1, 'error_message': 'None', 'history':image.history()}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'imageHistoryStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)
        
    def removeImage(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            name = data['name']
            try:
                if name == 0:
                    action = client.images.prune()    
                else:
                    action = client.images.remove(name)
                print action
            except docker.errors.APIError as err:
                data_ret = {'removeImageStatus': 0, 'error_message': str(err)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'removeImageStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
                                
            
            data_ret = {'removeImageStatus': 1, 'error_message': 'None'}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'removeImageStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)        
        
    # Internal function for recreating containers
    
    def doRecreateContainer(self, userID, data, con):
        try:
            name = data['name']
            unlisted = data['unlisted'] # Pass this as 1 if image is not known for container
            image = data['image']
            tag = data['tag']
            env = data['env']
            port = data['ports']
            memory = data['memory']
            
            if image == 'unknown':
                return "Image name not known"
            # Call container delete function
            delStatus = self.submitContainerDeletion(userID, data, True)
            if delStatus != 0:
                return delStatus
                
            print env
            containerArgs = {'image':image+":"+tag,
                            'detach':True,
                            'name':name,
                            'ports':port,
                            'environment':env,
                            'mem_limit': memory * 1048576}
                        
            if con.startOnReboot == 1:
                containerArgs['restart_policy'] = {"Name": "always"}
            
            container = client.containers.run(**containerArgs)
            con.cid = container.id
            con.save()
            
            return 0
        except BaseException, msg:
            return str(msg)
        
    def saveContainerSettings(self, userID = None, data = None):
        try:

            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'deleteWebsite') == 0:
                return ACLManager.loadErrorJson('websiteDeleteStatus', 0)

            name = data['name']
            memory = data['memory']
            startOnReboot = data['startOnReboot']
            envList = data['envList']
            
            if startOnReboot == True:
                startOnReboot = 1
                rPolicy = {"Name": "always"}
            else:
                startOnReboot = 0
                rPolicy = {}
            
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                data_ret = {'saveSettingsStatus': 0, 'error_message': 'Container does not exist'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'saveSettingsStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            
            try:
                container.update(mem_limit=memory * 1048576,
                                restart_policy = rPolicy)
            except docker.errors.APIError as err:
                data_ret = {'saveSettingsStatus': 0, 'error_message': str(err)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)    
            
            con = Containers.objects.get(name=name)
            con.memory = memory
            con.startOnReboot = startOnReboot
            
            if 'envConfirmation' in data and data['envConfirmation']:
                # Formatting envList for usage
                envDict = {}
                for key, value in envList.iteritems():
                    # Todo: Add proper filters and checks for each variable 
                    if (value['name'] != '') or (value['value'] != ''):
                        envDict[value['name']] = value['value']
                
                print envDict
                # Prepare data for recreate function
                data = {
                    'name': name,
                    'unlisted': 0, 
                    'image': con.image,
                    'tag': con.tag,
                    'env': envDict,
                    'ports': json.loads(con.ports), # No filter needed now as its ports are filtered when adding to database
                    'memory': con.memory
                }

                recreateStatus = self.doRecreateContainer(userID, data, con)
                if recreateStatus != 0:
                    data_ret = {'saveSettingsStatus': 0, 'error_message': str(recreateStatus)}
                    json_data = json.dumps(data_ret)
                    return HttpResponse(json_data)    
                
                con.env = json.dumps(envDict)
                con.save()                       
                
            data_ret = {'saveSettingsStatus': 1, 'error_message': 'None'}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'saveSettingsStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)            
                
    def recreateContainer(self, userID = None, data = None):
        try:
            currentACL = ACLManager.loadedACL(userID)
            if ACLManager.currentContextPermission(currentACL, 'recreateContainer') == 0:
                return ACLManager.loadErrorJson('recreateContainerStatus', 0)

            name = data['name']
            
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound as err:
                data_ret = {'recreateContainerStatus': 0, 'error_message': 'Container does not exist'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
            except:
                data_ret = {'recreateContainerStatus': 0, 'error_message': 'Unknown'}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)
                        
            con = Containers.objects.get(name=name)
            
            # Prepare data for recreate function
            data = {
                'name': name,
                'unlisted': 0,
                'image': con.image,
                'tag': con.tag,
                'env': json.loads(con.env),
                'ports': json.loads(con.ports), # No filter needed now as its ports are filtered when adding to database
                'memory': con.memory
            }
            
            recreateStatus = self.doRecreateContainer(userID, data, con)
            if recreateStatus != 0:
                data_ret = {'recreateContainerStatus': 0, 'error_message': str(recreateStatus)}
                json_data = json.dumps(data_ret)
                return HttpResponse(json_data)    
            
            data_ret = {'recreateContainerStatus': 1, 'error_message': 'None'}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException, msg:
            data_ret = {'recreateContainerStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)  