import os #gør det muligt at interagerer med ens operativ system så du kan finde filer og mapper
import shutil #gør det mulgt at lave filoperationer så som at kopiere filer og mapper
from datetime import datetime # gør det muligt at hente dato og tid

# oprindelige mappe route 
source_dirs = [
    "/home/eson/TimeZone/"
    #"C:\\Users\\TobiasBissø\\Desktop\\static", # grunden til man bruger dobbelt \\ er fordi af et \ bruges som escape karakter i python
    #"C:\\Users\\TobiasBissø\\Desktop\\job ansøgning" #man kan bruge r foran hele stien for at undgå at bruge \\
]
# routen til hvor backup skal være
backup_root_dir = "/home/eson/backupfun/TimeZone_backup"

#tidsstemple 
timestamp = datetime.now().strftime('%Y-%m-%d.%H_%M_%S') 


for source_dir in source_dirs: # går igennem alle de mapper der er i source_dirs
    folder_name = os.path.basename(source_dir) # henter mappperne fra source_dirs
    backup_dir = os.path.join(backup_root_dir, f"{folder_name}_backup-{timestamp}") 
    # os.path.join gør det muligt at sammensætte stier på en platform så det virker i både windows og linux
    try:
        shutil.copytree(source_dir, backup_dir, ignore=shutil.ignore_patterns('.git')) #kopierer indholdet fra source_dir over i backup_dir. ignorerer mapper/filer der hedder .git.
        print(f'backup fuldført:{backup_dir}') # hvis backupen er en succes kommer den her besked
    except Exception as e:
        print(f'backup ikke gennemført: {e}') # hvis der er en fejl i backupen så vil den vise det her.

backups = [mappe_list for mappe_list in os.listdir(backup_root_dir) if os.path.isdir(os.path.join(backup_root_dir, mappe_list))]
#denne for loop går den igennem listen af mapper som er i vores backup mappe og gør at vi kun får mapperne og ikke filerne.
backups =sorted(backups) # sætter dem i rækkefølge så den ældste backup kommer først

while len(backups) > 3: #mere end 3 backups så vil den slette den ældste backup
    ældeste_backup = backups.pop(0) # i python fungere pop til slette noget i specifikt sted. 
    route= os.path.join(backup_root_dir, ældeste_backup) # gør den kan finde vej til den ældste backup 
    try: 
        shutil.rmtree(route)# her betyder rmtree(remove tree) at den sletter hele mappen og alt indholdet 
        print(f"gennemført fjernelse af {ældeste_backup}")
    except Exception as e:
        print(f'der skete en fejl, sletning mislykkes: {e}')