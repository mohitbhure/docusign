# docusign

 Prequisites:

 1) You must have node 16 or greater installed on your system
 2) You must have mongodb setup and working on your system

 Installation:

 1) Take checkout of the repository
 2) Run cd docusign/
 3) Run npm install
 4) Run node index.js and project will bootup at 8080 port
 5) Go to http://localhost:8080/


 Setup using Docker:

 Prequisites:

 You should have docker running on your system

 Installation:

 1) Go to project directory
 2) First we need to install mongodb. So we pull the latest mongodb image using the following command

 docker pull mongo:latest

 This will install the latest mongodb

 3) To generate the docker image for the project run the following command:

    docker build -t docusign .

 4) Before running the two images we need to create a network which will be used for communication between both the images. Run the following command to create a network:

 docker network create node-webapp-network

 5) Now we run the mongodb image using the following command:

 docker run -d -p 27017:27017 --network node-webapp-network --name mongodb mongo:latest

 6) Run the docusign image using the following command:

  docker run -d -p 8080:8080 --network node-webapp-network --name docusign docusign


Now the project will be running at http://localhost:8080/