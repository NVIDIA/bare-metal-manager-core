FROM carbide as carbide-api
ADD dev/deployment/carbide-api/wait-for-pg /usr/local/bin
ADD dev/deployment/carbide-api/wait-for-carbide-migrations /usr/local/bin
EXPOSE 1079
CMD ["/opt/carbide/carbide-api", "run" ]

