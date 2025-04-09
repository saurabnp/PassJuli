import sys,os
def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
    return os.path.abspath(os.path.join(base_path, relative_path))

def get_appdata_path():
    """Returns the path to the AppData folder of the current user, specifically for your application."""
    app_name = "PassJuli"
    appdata = os.getenv('APPDATA')
    if not appdata:
        appdata = os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming')
    appdata_folder = os.path.join(appdata, app_name)
    
    if not os.path.exists(appdata_folder):
        os.makedirs(appdata_folder)
    
    return appdata_folder
