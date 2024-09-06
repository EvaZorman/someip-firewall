DOCKER_PORTS="-p 30499:30499/tcp -p 224.224.224.245:30490:30490/udp"
DOCKER_CAP_ADD="NET_ADMIN"
DOCKER_NET="someip-firewall"
DOCKER_VOL=".:/ws/service"

docker run -v $DOCKER_VOL \
       --net $DOCKER_NET \
       --cap-add=$DOCKER_CAP_ADD \
       $DOCKER_PORTS \
       -it someip-service
