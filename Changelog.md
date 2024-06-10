# **NoireC2 Changelog**

## **General**

+ Changed the formatting of the todo list

## **Server side**

+ Removed unnecessary debug print statements
+ Fixed incorrect web response when a client had no tasks
+ Added account deletion page - admins can delete all accounts (apart from the 'admin' account), users with permission to delete users can delete all non admin users and users can delete themselves
+ Added 'owner' and 'nickname' columns to Device table
+ Added 'uID' handling from a client to the server
+ Minor updates and html cleanup to all web pages
+ Clients page will now show possible JWT's to use in a dropdown
+ Added group deletion page - only admins can delete groups (apart from the 'admins' group)
+ Updated settings page to show new settings

## **Client side**

+ Added handling of uID/owner of client executable
