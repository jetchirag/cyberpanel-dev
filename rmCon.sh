docker stop $(docker ps -aq)
docker rm $(docker ps -aq)

./manage.py shell < Conrm.py
