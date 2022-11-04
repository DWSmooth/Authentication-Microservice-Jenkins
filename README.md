# Authentication microservice fork for Jenkins

This is one of the Jenkins microservice pipeline scripts created to build a maven repository and push it to an AWS Container.

## Some details

The pipeline script is in the /dev/ branch.
Its last status is functioning, although on a basic EC2 it ate up all resources from a single agent for more than an hour without finishing.
Run from a local Jenkins service, it was able to build and push in about 40 minutes over a 0.5 Mbps up connection.
