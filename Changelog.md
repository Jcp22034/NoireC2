# **General**
+ Added ``Changelog.md``
+ Added ``todo.md`` 

# **Server side**
+ Removed unnecessary Device and Group class functions
+ Removed unnecessary User table creation string
+ Added Task class & database table to handle tasks
+ Added task HTTP client handling via contact pages/paths
+ Tweaked ``config.json`` preset
+ Tweaked ``/overview`` page
+ Added ``/clients`` page for client interaction
+ Added task parsing & database entry
+ Removed unnecessary User salt field
+ Changed ``.get(jwt)`` for ``.filter_by(jwt=jwt).all()`` where applicable
+ Improved task detection for tasks that need to run
+ Added Group and User table permission fields

# **Client side**
+ Refactored setup function/s
+ Added docstrings for transparancy
+ Added task recieving, parsing & running
+ Added mss library for screenshots
+ Added task response