##### Requirements
- credentials.json 
- > You can get this file by going to your google console and downloading your credentials. Then copy it to the root dir of the project and renaming it to credentials.json

# Notes
- Developer needs to activate gmail for their account
> https://console.cloud.google.com/apis/library/
- Then download the needed credentials.json from there
> _On your gmail console: add your email as a test email_

##### How it parses body
```
message_body = subject:recipient:message
```
