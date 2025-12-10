#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Obfuscator v2.0 - Outil d'obfuscation Python avancé
Pour démonstrations de sensibilisation en sécurité

Auteur: Consultant Cybersécurité
Usage: python obfuscator_v2.py <fichier.py> [options]
"""

import os
import sys
import base64
import zlib
import random
import string
import argparse
import marshal
import hashlib
from datetime import datetime
from typing import List, Tuple, Optional

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Configuration de l'obfuscateur"""
    VERSION = "2.0.0"
    CHUNK_SIZE_MIN = 6
    CHUNK_SIZE_MAX = 18
    DEAD_CODE_PROBABILITY = 0.3
    VAR_NAME_LENGTH = 12
    MAX_LAYERS = 5

# =============================================================================
# UTILITAIRES
# =============================================================================

class Utils:
    """Fonctions utilitaires"""

    @staticmethod
    def random_string(length: int = 12, prefix: str = '_') -> str:
        """Génère une chaîne aléatoire valide comme nom de variable Python"""
        chars = string.ascii_letters + '_'
        first_char = random.choice(string.ascii_letters + '_')
        rest = ''.join(random.choices(chars + string.digits, k=length-1))
        return prefix + first_char + rest

    @staticmethod
    def random_int(min_val: int = 0, max_val: int = 99999) -> int:
        """Génère un entier aléatoire"""
        return random.randint(min_val, max_val)

    @staticmethod
    def to_hex_string(data: str) -> str:
        """Convertit une chaîne en séquences hexadécimales"""
        return ''.join(f'\\x{ord(c):02x}' for c in data)

    @staticmethod
    def to_octal_string(data: str) -> str:
        """Convertit une chaîne en séquences octales"""
        return ''.join(f'\\{ord(c):03o}' for c in data)

    @staticmethod
    def to_unicode_string(data: str) -> str:
        """Convertit une chaîne en séquences unicode"""
        return ''.join(f'\\u{ord(c):04x}' for c in data)

    @staticmethod
    def chunk_string(data: str, chunk_size: int = 10) -> List[str]:
        """Découpe une chaîne en morceaux"""
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

# =============================================================================
# GÉNÉRATEURS DE CODE MORT (Dead Code)
# =============================================================================

class DeadCodeGenerator:
    """Génère du code mort pour obscurcir le flux"""

    @staticmethod
    def generate_variable_assignment() -> str:
        """Génère une assignation de variable inutile"""
        var = Utils.random_string(8)
        value_type = random.choice(['int', 'str', 'list', 'dict', 'lambda'])

        if value_type == 'int':
            return f"{var} = {Utils.random_int()}"
        elif value_type == 'str':
            return f'{var} = "{Utils.random_string(6)}"'
        elif value_type == 'list':
            items = [str(Utils.random_int(0, 100)) for _ in range(random.randint(2, 5))]
            return f"{var} = [{', '.join(items)}]"
        elif value_type == 'dict':
            return f'{var} = {{"{Utils.random_string(4)}": {Utils.random_int()}}}'
        else:
            return f"{var} = lambda x: x + {Utils.random_int(1, 100)}"

    @staticmethod
    def generate_conditional() -> str:
        """Génère un bloc conditionnel qui ne s'exécute jamais"""
        var = Utils.random_string(8)
        templates = [
            f"if False:\n    {var} = {Utils.random_int()}",
            f"if 0:\n    {var} = {Utils.random_int()}",
            f"if '' and None:\n    {var} = {Utils.random_int()}",
            f"if {Utils.random_int()} < 0 and {Utils.random_int()} > 99999:\n    {var} = {Utils.random_int()}",
        ]
        return random.choice(templates)

    @staticmethod
    def generate_loop() -> str:
        """Génère une boucle qui ne s'exécute jamais"""
        var = Utils.random_string(8)
        templates = [
            f"for {var} in []:\n    pass",
            f"while False:\n    {var} = {Utils.random_int()}",
            f"for {var} in range(0):\n    pass",
        ]
        return random.choice(templates)

    @staticmethod
    def generate_function() -> str:
        """Génère une fonction inutile"""
        func_name = Utils.random_string(10)
        var = Utils.random_string(6)
        return f"def {func_name}({var}={Utils.random_int()}):\n    return {var} * {Utils.random_int(1, 10)}"

    @staticmethod
    def generate_class() -> str:
        """Génère une classe vide inutile"""
        class_name = Utils.random_string(10, prefix='_C')
        return f"class {class_name}:\n    {Utils.random_string(6)} = {Utils.random_int()}"

    @staticmethod
    def generate_try_except() -> str:
        """Génère un bloc try/except inutile"""
        var = Utils.random_string(8)
        return f"try:\n    {var} = {Utils.random_int()}\nexcept:\n    pass"

    @classmethod
    def generate_random(cls) -> str:
        """Génère un type aléatoire de code mort"""
        generators = [
            cls.generate_variable_assignment,
            cls.generate_conditional,
            cls.generate_loop,
            cls.generate_function,
            cls.generate_class,
            cls.generate_try_except,
        ]
        return random.choice(generators)()

# =============================================================================
# ENCODEURS
# =============================================================================

class Encoders:
    """Différentes méthodes d'encodage"""

    @staticmethod
    def xor_encode(data: bytes, key: int) -> bytes:
        """Encodage XOR avec une clé"""
        return bytes([b ^ key for b in data])

    @staticmethod
    def rot13_encode(data: str) -> str:
        """Encodage ROT13"""
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def reverse_encode(data: str) -> str:
        """Inverse la chaîne"""
        return data[::-1]

    @staticmethod
    def caesar_encode(data: str, shift: int) -> str:
        """Encodage César avec décalage personnalisé"""
        result = []
        for char in data:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)

# =============================================================================
# TECHNIQUES D'OBFUSCATION
# =============================================================================

class ObfuscationTechniques:
    """Différentes techniques d'obfuscation"""

    @staticmethod
    def base64_layer(content: str) -> Tuple[str, str]:
        """Couche d'obfuscation Base64"""
        encoded = base64.b64encode(content.encode('utf-8')).decode()
        var_data = Utils.random_string()

        # Découpage en chunks de taille aléatoire
        chunk_size = random.randint(Config.CHUNK_SIZE_MIN, Config.CHUNK_SIZE_MAX)
        chunks = Utils.chunk_string(encoded, chunk_size)

        lines = [f'{var_data} = ""']
        for chunk in chunks:
            encoding_method = random.choice(['hex', 'octal', 'unicode', 'plain'])
            if encoding_method == 'hex':
                lines.append(f'{var_data} += "{Utils.to_hex_string(chunk)}"')
            elif encoding_method == 'octal':
                lines.append(f'{var_data} += "{Utils.to_octal_string(chunk)}"')
            elif encoding_method == 'unicode':
                lines.append(f'{var_data} += "{Utils.to_unicode_string(chunk)}"')
            else:
                lines.append(f'{var_data} += "{chunk}"')

            # Insertion aléatoire de dead code
            if random.random() < Config.DEAD_CODE_PROBABILITY:
                lines.append(DeadCodeGenerator.generate_random())

        decode_line = f'exec(__import__("base64").b64decode({var_data}).decode("utf-8"))'
        lines.append(decode_line)

        return '\n'.join(lines), var_data

    @staticmethod
    def zlib_layer(content: str) -> Tuple[str, str]:
        """Couche d'obfuscation Zlib + Base64"""
        compressed = zlib.compress(content.encode('utf-8'), level=9)
        encoded = base64.b64encode(compressed).decode()

        var_data = Utils.random_string()
        var_zlib = Utils.random_string()
        var_b64 = Utils.random_string()

        chunk_size = random.randint(Config.CHUNK_SIZE_MIN, Config.CHUNK_SIZE_MAX)
        chunks = Utils.chunk_string(encoded, chunk_size)

        lines = [f'{var_data} = ""']
        for chunk in chunks:
            hex_chunk = Utils.to_hex_string(chunk)
            lines.append(f'{var_data} += "{hex_chunk}"')
            if random.random() < Config.DEAD_CODE_PROBABILITY:
                lines.append(DeadCodeGenerator.generate_random())

        lines.extend([
            f'{var_b64} = __import__("base64")',
            f'{var_zlib} = __import__("zlib")',
            f'exec({var_zlib}.decompress({var_b64}.b64decode({var_data})).decode("utf-8"))'
        ])

        return '\n'.join(lines), var_data

    @staticmethod
    def xor_layer(content: str) -> Tuple[str, str]:
        """Couche d'obfuscation XOR + Base64"""
        xor_key = random.randint(1, 255)
        xored = Encoders.xor_encode(content.encode('utf-8'), xor_key)
        encoded = base64.b64encode(xored).decode()

        var_data = Utils.random_string()
        var_key = Utils.random_string()
        var_decoded = Utils.random_string()

        chunk_size = random.randint(Config.CHUNK_SIZE_MIN, Config.CHUNK_SIZE_MAX)
        chunks = Utils.chunk_string(encoded, chunk_size)

        lines = [f'{var_data} = ""', f'{var_key} = {xor_key}']
        for chunk in chunks:
            hex_chunk = Utils.to_hex_string(chunk)
            lines.append(f'{var_data} += "{hex_chunk}"')
            if random.random() < Config.DEAD_CODE_PROBABILITY:
                lines.append(DeadCodeGenerator.generate_random())

        lines.extend([
            f'{var_decoded} = __import__("base64").b64decode({var_data})',
            f'{var_decoded} = bytes([b ^ {var_key} for b in {var_decoded}])',
            f'exec({var_decoded}.decode("utf-8"))'
        ])

        return '\n'.join(lines), var_data

    @staticmethod
    def marshal_layer(content: str) -> Tuple[str, str]:
        """Couche d'obfuscation Marshal (bytecode)"""
        # Compile le code en bytecode
        code_obj = compile(content, '<obfuscated>', 'exec')
        marshaled = marshal.dumps(code_obj)
        encoded = base64.b64encode(marshaled).decode()

        var_data = Utils.random_string()
        var_marshal = Utils.random_string()

        chunk_size = random.randint(Config.CHUNK_SIZE_MIN, Config.CHUNK_SIZE_MAX)
        chunks = Utils.chunk_string(encoded, chunk_size)

        lines = [f'{var_data} = ""']
        for chunk in chunks:
            hex_chunk = Utils.to_hex_string(chunk)
            lines.append(f'{var_data} += "{hex_chunk}"')
            if random.random() < Config.DEAD_CODE_PROBABILITY:
                lines.append(DeadCodeGenerator.generate_random())

        lines.extend([
            f'{var_marshal} = __import__("marshal")',
            f'exec({var_marshal}.loads(__import__("base64").b64decode({var_data})))'
        ])

        return '\n'.join(lines), var_data

    @staticmethod
    def multi_xor_layer(content: str) -> Tuple[str, str]:
        """Couche d'obfuscation Multi-XOR avec clés multiples"""
        keys = [random.randint(1, 255) for _ in range(3)]
        data = content.encode('utf-8')

        # Triple XOR
        for key in keys:
            data = Encoders.xor_encode(data, key)

        encoded = base64.b64encode(data).decode()

        var_data = Utils.random_string()
        var_keys = Utils.random_string()
        var_result = Utils.random_string()

        chunk_size = random.randint(Config.CHUNK_SIZE_MIN, Config.CHUNK_SIZE_MAX)
        chunks = Utils.chunk_string(encoded, chunk_size)

        lines = [
            f'{var_data} = ""',
            f'{var_keys} = {keys[::-1]}'  # Inverser pour décodage
        ]

        for chunk in chunks:
            hex_chunk = Utils.to_hex_string(chunk)
            lines.append(f'{var_data} += "{hex_chunk}"')
            if random.random() < Config.DEAD_CODE_PROBABILITY:
                lines.append(DeadCodeGenerator.generate_random())

        lines.extend([
            f'{var_result} = __import__("base64").b64decode({var_data})',
            f'for _k in {var_keys}:',
            f'    {var_result} = bytes([b ^ _k for b in {var_result}])',
            f'exec({var_result}.decode("utf-8"))'
        ])

        return '\n'.join(lines), var_data

    @staticmethod
    def lambda_layer(content: str) -> Tuple[str, str]:
        """Couche d'obfuscation via lambdas imbriquées"""
        encoded = base64.b64encode(content.encode('utf-8')).decode()

        var_data = Utils.random_string()
        var_lambda = Utils.random_string()
        var_exec = Utils.random_string()

        chunk_size = random.randint(Config.CHUNK_SIZE_MIN, Config.CHUNK_SIZE_MAX)
        chunks = Utils.chunk_string(encoded, chunk_size)

        lines = [f'{var_data} = ""']
        for chunk in chunks:
            hex_chunk = Utils.to_hex_string(chunk)
            lines.append(f'{var_data} += "{hex_chunk}"')

        # Obfuscation via lambdas
        lines.extend([
            f'{var_lambda} = lambda x: __import__("base64").b64decode(x).decode("utf-8")',
            f'{var_exec} = lambda x: exec(x)',
            f'{var_exec}({var_lambda}({var_data}))'
        ])

        return '\n'.join(lines), var_data

# =============================================================================
# OBFUSCATEUR PRINCIPAL
# =============================================================================

class Obfuscator:
    """Classe principale d'obfuscation"""

    def __init__(self, layers: int = 2, add_anti_debug: bool = False,
                 add_header: bool = True, technique: str = 'auto'):
        self.layers = min(layers, Config.MAX_LAYERS)
        self.add_anti_debug = add_anti_debug
        self.add_header = add_header
        self.technique = technique

        self.techniques = {
            'base64': ObfuscationTechniques.base64_layer,
            'zlib': ObfuscationTechniques.zlib_layer,
            'xor': ObfuscationTechniques.xor_layer,
            'marshal': ObfuscationTechniques.marshal_layer,
            'multi_xor': ObfuscationTechniques.multi_xor_layer,
            'lambda': ObfuscationTechniques.lambda_layer,
        }

    def _generate_header(self) -> str:
        """Génère l'en-tête du fichier obfusqué"""
        return f'''# -*- coding: utf-8 -*-
# Obfuscated with Obfuscator v{Config.VERSION}
# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Hash: {Utils.random_string(32, prefix='')}
'''

    def _generate_anti_debug(self) -> str:
        """Génère du code anti-débogage (pour démonstration)"""
        var_sys = Utils.random_string()
        var_trace = Utils.random_string()

        return f'''
# Anti-debug check (demonstration only)
{var_sys} = __import__("sys")
{var_trace} = {var_sys}.gettrace()
if {var_trace} is not None:
    {var_sys}.exit(0)
'''

    def _select_technique(self) -> callable:
        """Sélectionne une technique d'obfuscation"""
        if self.technique == 'auto':
            return random.choice(list(self.techniques.values()))
        elif self.technique in self.techniques:
            return self.techniques[self.technique]
        else:
            return self.techniques['base64']

    def obfuscate(self, content: str) -> str:
        """Obfusque le contenu avec plusieurs couches"""
        result = content

        # Application des couches d'obfuscation
        for i in range(self.layers):
            technique = self._select_technique()
            result, _ = technique(result)

        # Assemblage final
        final_code = []

        if self.add_header:
            final_code.append(self._generate_header())

        # Imports obfusqués
        final_code.append(DeadCodeGenerator.generate_variable_assignment())
        final_code.append(DeadCodeGenerator.generate_function())

        if self.add_anti_debug:
            final_code.append(self._generate_anti_debug())

        # Code mort initial
        for _ in range(random.randint(2, 5)):
            final_code.append(DeadCodeGenerator.generate_random())

        # Code obfusqué principal
        final_code.append(result)

        # Code mort final
        for _ in range(random.randint(1, 3)):
            final_code.append(DeadCodeGenerator.generate_random())

        return '\n'.join(final_code)

    def obfuscate_file(self, input_path: str, output_path: Optional[str] = None) -> str:
        """Obfusque un fichier Python"""
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Fichier non trouvé: {input_path}")

        if not input_path.endswith('.py'):
            raise ValueError("Le fichier doit être un fichier Python (.py)")

        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        obfuscated = self.obfuscate(content)

        if output_path is None:
            base_name = os.path.splitext(input_path)[0]
            output_path = f"{base_name}_obfuscated.py"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(obfuscated)

        return output_path

# =============================================================================
# INTERFACE EN LIGNE DE COMMANDE
# =============================================================================

class Colors:
    """Codes couleur ANSI pour le terminal"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Affiche la bannière"""
    banner = f'''
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   {Colors.MAGENTA}██████╗ ██████╗ ███████╗██╗   ██╗███████╗ ██████╗{Colors.CYAN}           ║
║   {Colors.MAGENTA}██╔═══██╗██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝{Colors.CYAN}          ║
║   {Colors.MAGENTA}██║   ██║██████╔╝█████╗  ██║   ██║███████╗██║     {Colors.CYAN}          ║
║   {Colors.MAGENTA}██║   ██║██╔══██╗██╔══╝  ██║   ██║╚════██║██║     {Colors.CYAN}          ║
║   {Colors.MAGENTA}╚██████╔╝██████╔╝██║     ╚██████╔╝███████║╚██████╗{Colors.CYAN}          ║
║   {Colors.MAGENTA} ╚═════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝{Colors.CYAN}          ║
║                                                               ║
║   {Colors.YELLOW}Python Obfuscator v{Config.VERSION}{Colors.CYAN}                                   ║
║   {Colors.WHITE}Pour démonstrations de sensibilisation sécurité{Colors.CYAN}             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
'''
    print(banner)

def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description='Obfuscateur Python avancé pour démonstrations de sécurité',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemples d'utilisation:
  %(prog)s script.py                     # Obfuscation basique
  %(prog)s script.py -l 3                # 3 couches d'obfuscation
  %(prog)s script.py -t xor -o out.py    # Technique XOR, sortie personnalisée
  %(prog)s script.py -l 4 --anti-debug   # Avec anti-débogage

Techniques disponibles:
  auto      - Sélection aléatoire (défaut)
  base64    - Encodage Base64 avec hex
  zlib      - Compression Zlib + Base64
  xor       - Chiffrement XOR + Base64
  multi_xor - Triple XOR + Base64
  marshal   - Compilation bytecode + Base64
  lambda    - Obfuscation via lambdas
        '''
    )

    parser.add_argument('file', nargs='?', help='Fichier Python à obfusquer')
    parser.add_argument('-o', '--output', help='Fichier de sortie')
    parser.add_argument('-l', '--layers', type=int, default=2,
                        help=f'Nombre de couches (1-{Config.MAX_LAYERS}, défaut: 2)')
    parser.add_argument('-t', '--technique', default='auto',
                        choices=['auto', 'base64', 'zlib', 'xor', 'multi_xor', 'marshal', 'lambda'],
                        help='Technique d\'obfuscation (défaut: auto)')
    parser.add_argument('--anti-debug', action='store_true',
                        help='Ajoute du code anti-débogage')
    parser.add_argument('--no-header', action='store_true',
                        help='Ne pas ajouter l\'en-tête')
    parser.add_argument('-v', '--version', action='version',
                        version=f'Obfuscator v{Config.VERSION}')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Mode interactif')

    args = parser.parse_args()

    print_banner()

    # Mode interactif
    if args.interactive or args.file is None:
        print(f"{Colors.CYAN}[?] Mode interactif{Colors.RESET}\n")

        file_path = input(f"{Colors.YELLOW}[>] Fichier à obfusquer: {Colors.RESET}").strip().strip('"\'')

        if not file_path:
            print(f"{Colors.RED}[!] Aucun fichier spécifié{Colors.RESET}")
            sys.exit(1)

        try:
            layers = int(input(f"{Colors.YELLOW}[>] Nombre de couches (1-{Config.MAX_LAYERS}) [2]: {Colors.RESET}") or "2")
        except ValueError:
            layers = 2

        technique = input(f"{Colors.YELLOW}[>] Technique (auto/base64/zlib/xor/multi_xor/marshal/lambda) [auto]: {Colors.RESET}") or "auto"
        anti_debug = input(f"{Colors.YELLOW}[>] Anti-debug? (o/n) [n]: {Colors.RESET}").lower() == 'o'

        args.file = file_path
        args.layers = layers
        args.technique = technique
        args.anti_debug = anti_debug

    # Validation
    if not os.path.isfile(args.file):
        print(f"{Colors.RED}[!] Erreur: Fichier non trouvé: {args.file}{Colors.RESET}")
        sys.exit(1)

    if not args.file.endswith('.py'):
        print(f"{Colors.RED}[!] Erreur: Le fichier doit être un .py{Colors.RESET}")
        sys.exit(1)

    # Obfuscation
    print(f"\n{Colors.CYAN}[*] Fichier source: {Colors.WHITE}{args.file}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Couches: {Colors.WHITE}{args.layers}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Technique: {Colors.WHITE}{args.technique}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Anti-debug: {Colors.WHITE}{'Oui' if args.anti_debug else 'Non'}{Colors.RESET}")
    print()

    try:
        obfuscator = Obfuscator(
            layers=args.layers,
            add_anti_debug=args.anti_debug,
            add_header=not args.no_header,
            technique=args.technique
        )

        output_path = obfuscator.obfuscate_file(args.file, args.output)

        # Statistiques
        original_size = os.path.getsize(args.file)
        obfuscated_size = os.path.getsize(output_path)
        ratio = obfuscated_size / original_size if original_size > 0 else 0

        print(f"{Colors.GREEN}[✓] Obfuscation réussie!{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Fichier de sortie: {Colors.WHITE}{output_path}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Taille originale: {Colors.WHITE}{original_size} octets{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Taille obfusquée: {Colors.WHITE}{obfuscated_size} octets{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Ratio: {Colors.WHITE}{ratio:.2f}x{Colors.RESET}")

    except Exception as e:
        print(f"{Colors.RED}[!] Erreur: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()