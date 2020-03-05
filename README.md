
# GeneXus Security API for Java

These are the source of the GeneXus Security API.

## Modules

| Name  | Description
|---|---
| SecurityAPICommons | Classes common to all GeneXusSecurityAPI modules, output is SecurityAPICommons.jar
| GeneXusCryptography | GeneXus Cryptography Module, output is GeneXusCryptography.jar
| GeneXusXmlSignature | GeneXus Xml Signature Module, output is GeneXusXmlSignature.jar
| GeneXusJWT | GeneXus Json Web Token Module, output is GeneXusJWT.jar
| GeneXusSftp | GeneXus SFTP Module, output is GeneXusSftp.jar
| GeneXusFtps | GeneXus FTPS Module, output is GeneXusFtps.jar (under development)

The dependencies between the projects are specified in each pom.xml within their directory.

# How to compile

## Requirements
- JDK 9 or greater
- Maven 3.6 or greater

# Instructions

## How to build all projects?
- ```mvn compile```

## How to build a specific project?
- ```cd <specific project dir>```
- ```mvn compile```

## How to package all or some project?
- ```mvn package```

## How to copy dependencies jar files to the dependency directory?
- ```cd java```
- ```mvn dependency:copy-dependencies```

  
## License

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

## GeneXus SecurityApi-Module GeneXus Wiki Documentation

https://wiki.genexus.com/commwiki/servlet/wiki?43916,Toc%3AGeneXus+Security+API

