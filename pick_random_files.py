import os
import random
import shutil

# cartella con tutti i file
src_dir = "/Users/micheleaversana/Documents/GitHub/smartbugs-wild/contracts"
# cartella con i 100 file già presi
existing_dir = "/Users/micheleaversana/Documents/GitHub/smartbugs/samples/SmartbugsWild"
# cartella di destinazione per i nuovi 50 file
dest_dir = "/Users/micheleaversana/Documents/GitHub/smartbugs/samples/SmartbugsWild2"

# lista di tutti i file nella cartella grande
all_files = set(os.listdir(src_dir))
# lista di file già usati
existing_files = set(os.listdir(existing_dir))

# calcolo i file disponibili
available_files = list(all_files - existing_files)

# seleziono 50 file a caso (senza replacement)
selected_files = random.sample(available_files, 50)

# copio i file scelti nella nuova cartella
for f in selected_files:
    shutil.copy(os.path.join(src_dir, f), os.path.join(dest_dir, f))

print(f"Copiati {len(selected_files)} file nella nuova cartella.")