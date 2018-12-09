/* Java script code for docker management */
var delayTimer = null;

app.controller('dockerImages', function($scope,$http) {
    $scope.tagList = [];
    $scope.imageTag = {};
    $("#errorMessage").hide();
    $scope.showInstallImage = true;
    $scope.showImageList = true;
    $scope.installImageError = false;
    $scope.installImageSuccess = false;
    $scope.installImageLoading = false;
    
    $scope.cancelInstall = function(){
        $scope.showInstallImage = false;
        $scope.showImageList = true;
        $scope.installImageError = false;
        $scope.installImageSuccess = false;
    }
    
    $scope.searchImages = function(){        
        clearTimeout(delayTimer);
        delayTimer = setTimeout(function() {

            $("#imageList").attr("pointer-events","none");

            url = "/docker/searchImage";
            var data = {
                string: $scope.searchString
            };
            var config = {
                headers : {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };

            $http.post(url, data,config).then(ListInitialDatas, cantLoadInitialDatas);

            function ListInitialDatas(response) {
                if (response.data.searchImageStatus === 1)
                {
                    $scope.images = response.data.matches;
                    console.log($scope.images)
                }
                else{
                    new PNotify({
                        title: 'Failed to complete request',
                        text: response.data.error,
                        type: 'error'
                    });
                }

                $("#imageList").removeAttr("pointer-events");

            }
            function cantLoadInitialDatas(response) {
                $("#imageList").removeAttr("pointer-events");
                new PNotify({
                    title: 'Failed to complete request',
                    type: 'error'
                });
            }
        }, 500);
    }
    
    $scope.installImage = function(image, tag){
        $("#installImagePanel button").attr("disabled", "disabled");
        $scope.installImageError = false;
        $scope.installImageLoading = true;
        $scope.installImageSuccess = false;
        url = "/docker/installImage";

        var data = {
            image: image,
            tag: tag
        };

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data,config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $("#installImagePanel button").removeAttr("disabled");
            $scope.installImageLoading = false;

            if (response.data.installImageStatus === 1)
            {
                $scope.installImageError = false;
                $scope.installImageSuccess = true;
            }
            else{
                $scope.installImageError = true;
                $scope.installImageSuccess = false;
                $scope.imageErrorMessage = response.data.error_message;
            }



        }
        function cantLoadInitialDatas(response) {
            $scope.installImageLoading = false;
            $("#installImagePanel button").removeAttr("disabled");
            $scope.installImageError = true;
            $scope.installImageSuccess = false;
            $scope.installImageError = "Failed to load";
        }
        
    }
    
    function populateTagList(image, page){
        url = "/docker/getTags?image="+image+"&page="+page+1;


        var params = {};

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
                }
            };


        $http.get(url, params, config).then(function(response){
            console.log(response)
            $scope.tagList[image].splice(-1,1);
            $scope.tagList[image] = $scope.tagList[image].concat(response.data);
            
            if (response.data.length !== 0){
                $scope.tagList[image].push("Load more");                
            }
        });
    }
    
    $scope.runContainer = function(image){
        $("#errorMessage").hide();
        if ($scope.imageTag[image] !== undefined) {
            $("#imageList").css("pointer-events","none");
        }
        else {
            $("#errorMessage").show();
            $scope.errorMessage = "Please select a tag";
        }
    }
  
    $scope.loadTags = function(){
        var pagesloaded = $(event.target).data('pageloaded');
        var image = event.target.id;
        
        if (!pagesloaded) {
            $scope.tagList[image] = ['Loading...'];
            $(event.target).data('pageloaded',1);
        
            populateTagList(image, pagesloaded);
//             $("#"+image+" option:selected").prop("selected", false);
        }
    }
    
    $scope.selectTag = function(){
        var image = event.target.id;
        var selectedTag = $('#'+image).find(":selected").text();
        
        if (selectedTag == 'Load more') {
            var pagesloaded = $(event.target).data('pageloaded');
            $(event.target).data('pageloaded', pagesloaded+1);
        
            populateTagList(image, pagesloaded);
        }
    }

});

/* Java script code to install Container */

app.controller('runContainer', function($scope,$http) {
    $scope.containerCreationLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;

    var statusFile;

    $scope.createContainer = function(){
        
        console.log($scope.iport);
        console.log($scope.portType);

        $scope.containerCreationLoading = true;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;

        $scope.currentStatus = "Starting creation..";

        url = "/docker/submitContainerCreation";

        var name = $scope.name;
        var tag = $scope.tag;
        var memory = $scope.memory;
        var websiteOwner = $scope.websiteOwner;
        var image = $scope.image

        var data = {
            name: name,
            tag: tag,
            memory: memory,
            websiteOwner: websiteOwner,
            image: image
        };
        
        $.each($scope.portType, function( port, protocol ) {
          data[port + "/" + protocol] = $scope.eport[port];
        });
        
        console.log(data)

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data,config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.createContainerStatus === 1)
            {
                $scope.currentStatus = "Successful. Redirecting...";
                window.location.href = "/docker/view/" + $scope.name
            }
            else{

                $scope.containerCreationLoading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;
            }



        }
        function cantLoadInitialDatas(response) {

            $scope.containerCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }
    };
    $scope.goBack = function () {
        $scope.containerCreationLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

});

/* Javascript code for listing containers */


app.controller('listContainers', function($scope,$http) {
    $scope.activeLog = "";
    $scope.assignActive = "";
    
    $scope.assignContainer = function(name){
        $("#assign").modal("show");
        $scope.assignActive = name;
    }
    
    $scope.submitAssignContainer = function(){
        url = "/docker/assignContainer";

        var data = {name: $scope.assignActive, admin: $scope.websiteOwner};

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);

        function ListInitialData(response) {

            if (response.data.assignContainerStatus === 1) {
                new PNotify({
                    title: 'Container assigned successfully',
                    type: 'success'
                });
                window.location.href = '/docker/listContainers';
            }
            else
            {
                new PNotify({
                    title: 'Unable to complete request',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
            $("#assign").modal("hide");
        }
        function cantLoadInitialData(response) {
            console.log("not good");
            new PNotify({
                title: 'Unable to complete request',
                type: 'error'
            });
            $("#assign").modal("hide");
        }
    }
    
    $scope.delContainer = function(name, unlisted=false){
        (new PNotify({
            title: 'Confirmation Needed',
            text: 'Are you sure?',
            icon: 'fa fa-question-circle',
            hide: false,
            confirm: {
                confirm: true
            },
            buttons: {
                closer: false,
                sticker: false
            },
            history: {
                history: false
            }
        })).get().on('pnotify.confirm', function() {
            url = "/docker/delContainer";

            var data = {name: name, unlisted: unlisted};

            var config = {
                headers : {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };

            $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);


            function ListInitialData(response) {
                console.log(response);

                if (response.data.delContainerStatus === 1) {
                    location.reload();
                }
                else
                {
                    $("#listFail").fadeIn();
                    $scope.errorMessage = response.data.error_message;
                }
            }
            function cantLoadInitialData(response) {
                console.log("not good");
                $scope.logs = "Error loading log";
            }
        })
    }  
    
    $scope.showLog = function(name, refresh = false){
        $scope.logs = "";
        if (refresh === false){
            $('#logs').modal('show');
            $scope.activeLog = name;
        }
        else {
            name = $scope.activeLog;
        }
        console.log(name)
        $scope.logs = "Loading...";       
        
        url = "/docker/getContainerLogs";

        var data = {name: name};

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            console.log(response);

            if (response.data.containerLogStatus === 1) {
                $scope.logs = response.data.containerLog;
            }
            else
            {
                $("#listFail").fadeIn();
                $scope.errorMessage = response.data.error_message;

            }
        }
        function cantLoadInitialData(response) {
            console.log("not good");
            $scope.logs = "Error loading log";
        }
    }

    url = "/docker/getContainerList";

    var data = {page: 1};

    var config = {
        headers : {
            'X-CSRFToken': getCookie('csrftoken')
        }
    };

    $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);


    function ListInitialData(response) {
        console.log(response);

        if (response.data.listContainerStatus === 1) {

            var finalData = JSON.parse(response.data.data);
            $scope.WebSitesList = finalData;
            console.log($scope.WebSitesList);
            $("#listFail").hide();
        }
        else
        {
            $("#listFail").fadeIn();
            $scope.errorMessage = response.data.error_message;

        }
    }
    function cantLoadInitialData(response) {
        console.log("not good");
    }


    $scope.getFurtherWebsitesFromDB = function(pageNumber) {

    var config = {
        headers : {
            'X-CSRFToken': getCookie('csrftoken')
        }
    };

    var data = {page: pageNumber};


    dataurl = "/docker/getContainerList";

    $http.post(dataurl, data,config).then(ListInitialData, cantLoadInitialData);


    function ListInitialData(response) {
        if (response.data.listContainerStatus ===1) {

            var finalData = JSON.parse(response.data.data);
            $scope.WebSitesList = finalData;
            $("#listFail").hide();
        }
        else
        {
            $("#listFail").fadeIn();
            $scope.errorMessage = response.data.error_message;
            console.log(response.data);

        }
    }
    function cantLoadInitialData(response) {
        console.log("not good");
    }



        };
});

/* Java script code for containerr home page */

app.controller('viewContainer', function($scope,$http) {
    $scope.cName = "";
    $scope.status = "";
    $scope.savingSettings = false;
    $scope.loadingTop = false;
    
    $scope.showTop = function(){
        $scope.topHead = [];
        $scope.topProcesses = [];
        $scope.loadingTop = true;
        $("#processes").modal("show");
        
        url = "/docker/getContainerTop";
        var data = {name: $scope.cName};
        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        
        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);
        function ListInitialData(response) {
            if (response.data.containerTopStatus === 1) {
                $scope.topHead = response.data.processes.Titles;
                $scope.topProcesses = response.data.processes.Processes;
            }
            else
            {
                new PNotify({
                    title: 'Unable to complete request',
                    text: response.data.error_message,
                    type: 'error'
                });

            }
            $scope.loadingTop = false;
        }
        function cantLoadInitialData(response) {
            PNotify.error({
              title: 'Unable to complete request',
              text: "Problem in connecting to server"
            });
            $scope.loadingTop = false;
        }
        
    }
    
    $scope.cRemove = function(){
        (new PNotify({
            title: 'Confirmation Needed',
            text: 'Are you sure?',
            icon: 'fa fa-question-circle',
            hide: false,
            confirm: {
                confirm: true
            },
            buttons: {
                closer: false,
                sticker: false
            },
            history: {
                history: false
            }
        })).get().on('pnotify.confirm', function() {
            
          url = "/docker/delContainer";
            var data = {name: $scope.cName, unlisted: false};
            var config = {
                headers : {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };

            $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);
            function ListInitialData(response) {
                if (response.data.delContainerStatus === 1) {
                    new PNotify({
                        title: 'Container deleted!',
                        text: 'Redirecting...',
                        type: 'success'
                    });
                    window.location.href = '/docker/listContainers';
                }
                else
                {
                    new PNotify({
                        title: 'Unable to complete request',
                        text: response.data.error_message,
                        type: 'error'
                    });

                }
            }
            function cantLoadInitialData(response) {
                PNotify.error({
                  title: 'Unable to complete request',
                  text: "Problem in connecting to server"
                });
            }
    })
    }
    
    $scope.refreshStatus = function(){
        url = "/docker/getContainerStatus";
        var data = {name: $scope.cName};
        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        
        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);
        function ListInitialData(response) {
            if (response.data.containerStatus === 1) {
                console.log(response.data.status);
                $scope.status = response.data.status;
            }
            else
            {
                new PNotify({
                    title: 'Unable to complete request',
                    text: response.data.error_message,
                    type: 'error'
                });

            }
        }
        function cantLoadInitialData(response) {
            PNotify.error({
              title: 'Unable to complete request',
              text: "Problem in connecting to server"
            });
        }
        
    }
    
    $scope.saveSettings = function(){
        url = "/docker/saveContainerSettings";
        $scope.savingSettings = true;
        var data = {name: $scope.cName, memory:$scope.memory, startOnReboot: $scope.startOnReboot};
        console.log(data)
        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        
        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);
        function ListInitialData(response) {
            if (response.data.saveSettingsStatus === 1) {
                new PNotify({
                    title: 'Settings Saved',
                    type: 'success'
                });
            }
            else
            {
                new PNotify({
                    title: 'Unable to complete request',
                    text: response.data.error_message,
                    type: 'error'
                });

            }
            $scope.savingSettings = false;
        }
        function cantLoadInitialData(response) {
            new PNotify({
              title: 'Unable to complete request',
              text: "Problem in connecting to server",
              type: 'error'
            });
            $scope.savingSettings = false;
        }
        
        if ($scope.startOnReboot === true){
            $scope.rPolicy="Yes";
        }
        else{
            $scope.rPolicy="No";
        }
        
    }
    
    $scope.cAction = function(action){
        console.log($scope.cName)
        url = "/docker/doContainerAction";
        var data = {name: $scope.cName, action: action};
        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        
        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            console.log(response);

            if (response.data.containerActionStatus === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Action completed',
                    type: 'success'
                });
                $scope.status = response.data.status;
                $scope.refreshStatus()
            }
            else
            {
                new PNotify({
                    title: 'Unable to complete request',
                    text: response.data.error_message,
                    type: 'error'
                });

            }
        }
        function cantLoadInitialData(response) {
            PNotify.error({
              title: 'Unable to complete request',
              text: "Problem in connecting to server"
            });
        }
        
    }
        
    $scope.loadLogs = function(name){
        $scope.logs = "Loading...";

        url = "/docker/getContainerLogs";

        var data = {name: name};

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            console.log(response);

            if (response.data.containerLogStatus === 1) {
                $scope.logs = response.data.containerLog;
            }
            else
            {
                $scope.logs = response.data.error_message;

            }
        }
        function cantLoadInitialData(response) {
            console.log("not good");
            $scope.logs = "Error loading log";
        }
    }    

});


/* Java script code for docker image management */
app.controller('manageImages', function($scope,$http) {
   $scope.getHistory = function(counter){
       var name = $("#"+counter).val()
       
       url = "/docker/getImageHistory";

        var data = {name: name};

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            console.log(response);

            if (response.data.imageHistoryStatus === 1) {
                $('#history').modal('show');
                $scope.historyList = response.data.history;
            }
            else
            {
                new PNotify({
                    title: 'Unable to complete request',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }
        function cantLoadInitialData(response) {
            new PNotify({
                title: 'Unable to complete request',
                text: response.data.error_message,
                type: 'error'
            });
        }
   }
   
   $scope.rmImage = function(counter){
       
       (new PNotify({
            title: 'Confirmation Needed',
            text: 'Are you sure?',
            icon: 'fa fa-question-circle',
            hide: false,
            confirm: {
                confirm: true
            },
            buttons: {
                closer: false,
                sticker: false
            },
            history: {
                history: false
            }
        })).get().on('pnotify.confirm', function() {
           
       if (counter == '0') {
           var name = 0;
       }
       else {
            var name = $("#"+counter).val()
        }
       
       url = "/docker/removeImage";

        var data = {name: name};

        var config = {
            headers : {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data,config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            console.log(response);

            if (response.data.removeImageStatus === 1) {
                new PNotify({
                    title: 'Image(s) removed',
                    type: 'success'
                });
                window.location.href = "/docker/manageImages";
            }
            else
            {
                new PNotify({
                    title: 'Unable to complete request',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }
        function cantLoadInitialData(response) {
            new PNotify({
                title: 'Unable to complete request',
                text: response.data.error_message,
                type: 'error'
            });
        }
           
        })
   }
});