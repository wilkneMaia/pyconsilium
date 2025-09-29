"""
Gerenciador de Senhas Melhorado - Sistema de Armazenamento Seguro
================================================================

Versão melhorada com:
- Melhor segurança (salt dinâmico, validação de entrada)
- Arquitetura mais limpa (separação de responsabilidades)
- Performance otimizada (cache inteligente, índices)
- Tratamento de erros robusto
- Sistema de logging
- Backup automático
"""

import os
import json
import hashlib
import base64
import getpass
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from contextlib import contextmanager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("password_manager.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


@dataclass
class PasswordData:
    """Estrutura de dados para senhas com validação."""

    service: str
    username: str
    encrypted_password: str
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""
    is_encrypted: bool = True

    def __post_init__(self):
        """Validação pós-inicialização."""
        if not self.service.strip():
            raise ValueError("Nome do serviço não pode estar vazio")
        if not self.username.strip():
            raise ValueError("Nome de usuário não pode estar vazio")
        if not self.encrypted_password:
            raise ValueError("Senha não pode estar vazia")

        # Sanitização
        self.service = self.service.strip()
        self.username = self.username.strip()
        self.notes = self.notes.strip()

        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at


class SecurityValidator:
    """Validador de segurança para entradas."""

    @staticmethod
    def validate_service_name(service: str) -> bool:
        """Valida nome do serviço."""
        if not service or len(service.strip()) < 2:
            return False
        # Verifica caracteres perigosos
        dangerous_chars = ["<", ">", '"', "'", "&", "|", ";", "`"]
        return not any(char in service for char in dangerous_chars)

    @staticmethod
    def validate_username(username: str) -> bool:
        """Valida nome de usuário."""
        if not username or len(username.strip()) < 2:
            return False
        # Verifica caracteres perigosos
        dangerous_chars = ["<", ">", '"', "'", "&", "|", ";", "`"]
        return not any(char in username for char in dangerous_chars)

    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """Valida força da senha com critérios aprimorados."""
        if not password:
            return {"valid": False, "score": 0, "issues": ["Senha vazia"]}

        issues = []
        score = 0

        # Comprimento
        if len(password) < 8:
            issues.append("Muito curta (mínimo 8 caracteres)")
        elif len(password) >= 12:
            score += 20
        else:
            score += 10

        # Caracteres
        if any(c.isupper() for c in password):
            score += 15
        else:
            issues.append("Sem maiúsculas")

        if any(c.islower() for c in password):
            score += 15
        else:
            issues.append("Sem minúsculas")

        if any(c.isdigit() for c in password):
            score += 15
        else:
            issues.append("Sem números")

        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 20
        else:
            issues.append("Sem caracteres especiais")

        # Padrões comuns
        common_patterns = ["123", "abc", "password", "qwerty", "admin", "123456"]
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 30
            issues.append("Padrões comuns detectados")

        # Sequências
        if any(
            password[i : i + 3] in "abcdefghijklmnopqrstuvwxyz"
            for i in range(len(password) - 2)
        ):
            score -= 10
            issues.append("Sequências detectadas")

        return {
            "valid": score >= 40,
            "score": max(0, min(100, score)),
            "issues": issues,
            "strength_level": SecurityValidator._get_strength_level(score),
        }

    @staticmethod
    def _get_strength_level(score: int) -> str:
        """Retorna nível de força baseado na pontuação."""
        if score >= 80:
            return "Muito Forte"
        elif score >= 60:
            return "Forte"
        elif score >= 40:
            return "Média"
        elif score >= 20:
            return "Fraca"
        else:
            return "Muito Fraca"


class MasterKeyManager:
    """Gerenciador da chave mestra com armazenamento em arquivo."""

    def __init__(self, key_file: str = "key.key"):
        """Inicializa o gerenciador de chave mestra."""
        self.key_file = Path(key_file)
        self._key_file_salt = (
            b"PyConsilium_Key_File_Salt_v1.0"  # Salt fixo para o arquivo de chave
        )

    def generate_master_key(self) -> str:
        """Gera uma chave mestra segura."""
        # Gera uma chave de 32 bytes (256 bits) usando secrets
        key_bytes = secrets.token_bytes(32)
        # Converte para string base64 para facilitar armazenamento
        return base64.urlsafe_b64encode(key_bytes).decode()

    def save_master_key(self, master_key: str) -> bool:
        """Salva a chave mestra em arquivo criptografado."""
        try:
            # Cria uma chave temporária baseada no salt fixo para criptografar a chave mestra
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._key_file_salt,
                iterations=100000,
            )

            # Usa um hash do sistema como "senha" para criptografar o arquivo de chave
            system_info = (
                f"{os.getenv('USER', 'unknown')}{os.getcwd()}{datetime.now().year}"
            )
            system_key = hashlib.sha256(system_info.encode()).digest()

            temp_key = base64.urlsafe_b64encode(kdf.derive(system_key))
            fernet = Fernet(temp_key)

            # Criptografa e salva a chave mestra
            encrypted_key = fernet.encrypt(master_key.encode())

            with open(self.key_file, "wb") as f:
                f.write(encrypted_key)

            # Define permissões restritivas (apenas o proprietário pode ler/escrever)
            os.chmod(self.key_file, 0o600)

            logger.info(f"Chave mestra salva em {self.key_file}")
            return True

        except Exception as e:
            logger.error(f"Erro ao salvar chave mestra: {e}")
            return False

    def load_master_key(self) -> Optional[str]:
        """Carrega a chave mestra do arquivo."""
        try:
            if not self.key_file.exists():
                return None

            # Mesmo processo de descriptografia
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._key_file_salt,
                iterations=100000,
            )

            system_info = (
                f"{os.getenv('USER', 'unknown')}{os.getcwd()}{datetime.now().year}"
            )
            system_key = hashlib.sha256(system_info.encode()).digest()

            temp_key = base64.urlsafe_b64encode(kdf.derive(system_key))
            fernet = Fernet(temp_key)

            with open(self.key_file, "rb") as f:
                encrypted_key = f.read()

            decrypted_key = fernet.decrypt(encrypted_key)
            return decrypted_key.decode()

        except Exception as e:
            logger.error(f"Erro ao carregar chave mestra: {e}")
            return None

    def key_exists(self) -> bool:
        """Verifica se o arquivo de chave existe."""
        return self.key_file.exists()

    def delete_key_file(self) -> bool:
        """Remove o arquivo de chave mestra."""
        try:
            if self.key_file.exists():
                self.key_file.unlink()
                logger.info("Arquivo de chave mestra removido")
                return True
            return False
        except Exception as e:
            logger.error(f"Erro ao remover arquivo de chave: {e}")
            return False


class SecureCryptoManager:
    """Gerenciador de criptografia melhorado com salt dinâmico."""

    def __init__(self, master_password: str, salt_file: str = "salt.bin"):
        """
        Inicializa o gerenciador de criptografia.

        Args:
            master_password (str): Senha mestra
            salt_file (str): Arquivo para armazenar o salt
        """
        self.master_password = master_password.encode()
        self.salt_file = Path(salt_file)
        self._key = self._derive_key()
        self._fernet = Fernet(self._key)

    def _derive_key(self) -> bytes:
        """Deriva chave de criptografia com salt dinâmico."""
        salt = self._get_or_create_salt()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(self.master_password))
        return key

    def _get_or_create_salt(self) -> bytes:
        """Obtém ou cria salt único."""
        if self.salt_file.exists():
            with open(self.salt_file, "rb") as f:
                return f.read()
        else:
            salt = secrets.token_bytes(32)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
            return salt

    def encrypt(self, data: str) -> str:
        """Criptografa dados."""
        try:
            encrypted_data = self._fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Erro ao criptografar: {e}")
            raise

    def decrypt(self, encrypted_data: str) -> str:
        """Descriptografa dados."""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self._fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Erro ao descriptografar: {e}")
            raise ValueError(f"Erro ao descriptografar dados: {e}")


class DatabaseManager:
    """Gerenciador de banco de dados SQLite para melhor performance."""

    def __init__(self, db_path: str = "passwords.db"):
        """Inicializa o gerenciador de banco de dados."""
        self.db_path = Path(db_path)
        self._init_database()

    def _init_database(self):
        """Inicializa o banco de dados com tabelas necessárias."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_encrypted BOOLEAN DEFAULT 1,
                    UNIQUE(service, username)
                )
            """
            )

            # Índices para melhor performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_service ON passwords(service)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_username ON passwords(username)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_created_at ON passwords(created_at)"
            )

    @contextmanager
    def _get_connection(self):
        """Context manager para conexão com banco de dados."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def save_password(self, password_data: PasswordData) -> bool:
        """Salva senha no banco de dados."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO passwords
                    (service, username, encrypted_password, notes, created_at, updated_at, is_encrypted)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        password_data.service,
                        password_data.username,
                        password_data.encrypted_password,
                        password_data.notes,
                        password_data.created_at,
                        password_data.updated_at,
                        password_data.is_encrypted,
                    ),
                )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Erro ao salvar senha: {e}")
            return False

    def get_password(self, service: str, username: str) -> Optional[PasswordData]:
        """Recupera senha específica."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT * FROM passwords
                    WHERE service = ? AND username = ?
                """,
                    (service, username),
                )

                row = cursor.fetchone()
                if row:
                    return PasswordData(
                        service=row["service"],
                        username=row["username"],
                        encrypted_password=row["encrypted_password"],
                        notes=row["notes"],
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        is_encrypted=bool(row["is_encrypted"]),
                    )
                return None
        except Exception as e:
            logger.error(f"Erro ao recuperar senha: {e}")
            return None

    def get_all_passwords(self) -> List[PasswordData]:
        """Recupera todas as senhas."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM passwords ORDER BY created_at DESC"
                )
                rows = cursor.fetchall()

                return [
                    PasswordData(
                        service=row["service"],
                        username=row["username"],
                        encrypted_password=row["encrypted_password"],
                        notes=row["notes"],
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        is_encrypted=bool(row["is_encrypted"]),
                    )
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Erro ao recuperar senhas: {e}")
            return []

    def search_passwords(self, query: str) -> List[PasswordData]:
        """Busca senhas por texto."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT * FROM passwords
                    WHERE service LIKE ? OR username LIKE ? OR notes LIKE ?
                    ORDER BY created_at DESC
                """,
                    (f"%{query}%", f"%{query}%", f"%{query}%"),
                )

                rows = cursor.fetchall()
                return [
                    PasswordData(
                        service=row["service"],
                        username=row["username"],
                        encrypted_password=row["encrypted_password"],
                        notes=row["notes"],
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        is_encrypted=bool(row["is_encrypted"]),
                    )
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Erro na busca: {e}")
            return []

    def delete_password(self, service: str, username: str) -> bool:
        """Remove senha do banco de dados."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM passwords
                    WHERE service = ? AND username = ?
                """,
                    (service, username),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Erro ao remover senha: {e}")
            return False


class BackupManager:
    """Gerenciador de backup automático."""

    def __init__(self, backup_dir: str = "backups"):
        """Inicializa o gerenciador de backup."""
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)

    def create_backup(self, db_path: str) -> Optional[str]:
        """Cria backup do banco de dados."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"backup_{timestamp}.db"

            # Copia o arquivo do banco
            import shutil

            shutil.copy2(db_path, backup_file)

            logger.info(f"Backup criado: {backup_file}")
            return str(backup_file)
        except Exception as e:
            logger.error(f"Erro ao criar backup: {e}")
            return None

    def cleanup_old_backups(self, days_to_keep: int = 30):
        """Remove backups antigos."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)

            for backup_file in self.backup_dir.glob("backup_*.db"):
                if backup_file.stat().st_mtime < cutoff_date.timestamp():
                    backup_file.unlink()
                    logger.info(f"Backup antigo removido: {backup_file}")
        except Exception as e:
            logger.error(f"Erro ao limpar backups: {e}")


class ImprovedPasswordManager:
    """Gerenciador de senhas melhorado com arquitetura limpa."""

    def __init__(self, master_password: str = None, key_file: str = "keys/key.key"):
        """
        Inicializa o gerenciador.

        Args:
            master_password (str, optional): Senha mestra. Se não fornecida, tenta carregar do arquivo.
            key_file (str): Arquivo para armazenar a chave mestra.
        """
        self.key_manager = MasterKeyManager(key_file)

        # Se não foi fornecida uma senha mestra, tenta carregar do arquivo
        if master_password is None:
            master_password = self._get_or_create_master_key()

        if master_password is None:
            raise ValueError("Não foi possível obter ou criar uma chave mestra")

        self.crypto_manager = SecureCryptoManager(master_password)
        self.db_manager = DatabaseManager()
        self.backup_manager = BackupManager()

        # Cache inteligente
        self._cache = {}
        self._cache_ttl = 300  # 5 minutos
        self._last_cache_update = 0

    def _get_or_create_master_key(self) -> Optional[str]:
        """Obtém a chave mestra do arquivo ou cria uma nova."""
        # Tenta carregar do arquivo
        master_key = self.key_manager.load_master_key()

        if master_key is not None:
            logger.info("Chave mestra carregada do arquivo")
            return master_key

        # Se não existe, gera uma nova
        print("🔑 Arquivo de chave mestra não encontrado.")
        print("📝 Gerando nova chave mestra automaticamente...")

        master_key = self.key_manager.generate_master_key()

        if self.key_manager.save_master_key(master_key):
            print("✅ Chave mestra gerada e salva automaticamente!")
            logger.info("Nova chave mestra gerada e salva")
            return master_key
        else:
            print("❌ Erro ao salvar chave mestra")
            return None

    def regenerate_master_key(self) -> Tuple[bool, str]:
        """
        Regenera a chave mestra (CUIDADO: isso torna todas as senhas inacessíveis!).

        Returns:
            Tuple[bool, str]: (sucesso, mensagem)
        """
        try:
            # Remove arquivo de chave existente
            self.key_manager.delete_key_file()

            # Gera nova chave
            new_key = self.key_manager.generate_master_key()

            if self.key_manager.save_master_key(new_key):
                logger.warning(
                    "Chave mestra regenerada - todas as senhas existentes estão inacessíveis!"
                )
                return (
                    True,
                    "Chave mestra regenerada com sucesso (ATENÇÃO: senhas existentes inacessíveis!)",
                )
            else:
                return False, "Erro ao salvar nova chave mestra"

        except Exception as e:
            logger.error(f"Erro ao regenerar chave mestra: {e}")
            return False, f"Erro ao regenerar chave: {str(e)}"

    def backup_key_file(self) -> Tuple[bool, str]:
        """Cria backup do arquivo de chave mestra."""
        try:
            if not self.key_manager.key_exists():
                return False, "Arquivo de chave mestra não existe"

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = (
                self.key_manager.key_file.parent / f"key_backup_{timestamp}.key"
            )

            import shutil

            shutil.copy2(self.key_manager.key_file, backup_path)

            logger.info(f"Backup da chave mestra criado: {backup_path}")
            return True, f"Backup criado: {backup_path}"

        except Exception as e:
            logger.error(f"Erro ao criar backup da chave: {e}")
            return False, f"Erro ao criar backup: {str(e)}"

    def _is_cache_valid(self) -> bool:
        """Verifica se o cache ainda é válido."""
        return (datetime.now().timestamp() - self._last_cache_update) < self._cache_ttl

    def _update_cache(self):
        """Atualiza o cache com dados do banco."""
        try:
            self._cache = {
                f"{p.service}:{p.username}": p
                for p in self.db_manager.get_all_passwords()
            }
            self._last_cache_update = datetime.now().timestamp()
        except Exception as e:
            logger.error(f"Erro ao atualizar cache: {e}")

    def _get_password_from_cache(
        self, service: str, username: str
    ) -> Optional[PasswordData]:
        """Recupera senha do cache."""
        if not self._is_cache_valid():
            self._update_cache()

        key = f"{service}:{username}"
        return self._cache.get(key)

    def add_password(
        self, service: str, username: str, password: str, notes: str = ""
    ) -> Tuple[bool, str]:
        """
        Adiciona nova senha com validação completa.

        Returns:
            Tuple[bool, str]: (sucesso, mensagem)
        """
        try:
            # Validações de entrada
            if not SecurityValidator.validate_service_name(service):
                return False, "Nome do serviço inválido"

            if not SecurityValidator.validate_username(username):
                return False, "Nome de usuário inválido"

            # Verifica se já existe
            if self._get_password_from_cache(service, username):
                return False, f"Senha já existe para {service} - {username}"

            # Valida força da senha
            strength_info = SecurityValidator.validate_password_strength(password)
            if not strength_info["valid"]:
                issues = ", ".join(strength_info["issues"])
                return False, f"Senha fraca: {issues}"

            # Cria e salva senha
            password_data = PasswordData(
                service=service,
                username=username,
                encrypted_password=self.crypto_manager.encrypt(password),
                notes=notes,
                is_encrypted=True,
            )

            if self.db_manager.save_password(password_data):
                # Cria backup automático
                self.backup_manager.create_backup(str(self.db_manager.db_path))

                # Atualiza cache
                self._update_cache()

                logger.info(f"Senha adicionada: {service} - {username}")
                return (
                    True,
                    f"Senha adicionada com sucesso (Força: {strength_info['strength_level']})",
                )
            else:
                return False, "Erro ao salvar no banco de dados"

        except Exception as e:
            logger.error(f"Erro ao adicionar senha: {e}")
            return False, f"Erro interno: {str(e)}"

    def get_password(self, service: str, username: str) -> Tuple[Optional[str], str]:
        """
        Recupera senha descriptografada.

        Returns:
            Tuple[Optional[str], str]: (senha, mensagem)
        """
        try:
            password_data = self._get_password_from_cache(service, username)
            if not password_data:
                return None, f"Senha não encontrada para {service} - {username}"

            decrypted_password = self.crypto_manager.decrypt(
                password_data.encrypted_password
            )
            return decrypted_password, "Senha recuperada com sucesso"

        except Exception as e:
            logger.error(f"Erro ao recuperar senha: {e}")
            return None, f"Erro ao descriptografar: {str(e)}"

    def update_password(
        self, service: str, username: str, new_password: str
    ) -> Tuple[bool, str]:
        """Atualiza senha existente."""
        try:
            # Valida nova senha
            strength_info = SecurityValidator.validate_password_strength(new_password)
            if not strength_info["valid"]:
                issues = ", ".join(strength_info["issues"])
                return False, f"Nova senha fraca: {issues}"

            # Verifica se existe
            existing = self._get_password_from_cache(service, username)
            if not existing:
                return False, f"Senha não encontrada para {service} - {username}"

            # Atualiza
            existing.encrypted_password = self.crypto_manager.encrypt(new_password)
            existing.updated_at = datetime.now().isoformat()

            if self.db_manager.save_password(existing):
                self._update_cache()
                logger.info(f"Senha atualizada: {service} - {username}")
                return (
                    True,
                    f"Senha atualizada com sucesso (Força: {strength_info['strength_level']})",
                )
            else:
                return False, "Erro ao salvar no banco de dados"

        except Exception as e:
            logger.error(f"Erro ao atualizar senha: {e}")
            return False, f"Erro interno: {str(e)}"

    def delete_password(self, service: str, username: str) -> Tuple[bool, str]:
        """Remove senha."""
        try:
            if self.db_manager.delete_password(service, username):
                self._update_cache()
                logger.info(f"Senha removida: {service} - {username}")
                return True, "Senha removida com sucesso"
            else:
                return False, f"Senha não encontrada para {service} - {username}"

        except Exception as e:
            logger.error(f"Erro ao remover senha: {e}")
            return False, f"Erro interno: {str(e)}"

    def search_passwords(self, query: str) -> List[PasswordData]:
        """Busca senhas por texto."""
        try:
            return self.db_manager.search_passwords(query)
        except Exception as e:
            logger.error(f"Erro na busca: {e}")
            return []

    def get_strength_report(self) -> Dict[str, Any]:
        """Gera relatório de força das senhas."""
        try:
            passwords = self.db_manager.get_all_passwords()

            if not passwords:
                return {"total": 0, "strength_distribution": {}, "weak_passwords": []}

            strength_levels = {}
            weak_passwords = []

            for password_data in passwords:
                try:
                    decrypted = self.crypto_manager.decrypt(
                        password_data.encrypted_password
                    )
                    strength_info = SecurityValidator.validate_password_strength(
                        decrypted
                    )
                    level = strength_info["strength_level"]

                    strength_levels[level] = strength_levels.get(level, 0) + 1

                    if strength_info["score"] < 40:
                        weak_passwords.append(
                            {
                                "service": password_data.service,
                                "username": password_data.username,
                                "score": strength_info["score"],
                                "level": level,
                            }
                        )
                except Exception as e:
                    logger.error(
                        f"Erro ao analisar força da senha {password_data.service}: {e}"
                    )

            return {
                "total": len(passwords),
                "strength_distribution": strength_levels,
                "weak_passwords": weak_passwords,
            }

        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return {"total": 0, "strength_distribution": {}, "weak_passwords": []}

    def export_passwords(self, filename: str = None) -> Tuple[bool, str]:
        """Exporta senhas para arquivo JSON."""
        try:
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"passwords_export_{timestamp}.json"

            passwords = self.db_manager.get_all_passwords()
            export_data = []

            for password_data in passwords:
                try:
                    decrypted_password = self.crypto_manager.decrypt(
                        password_data.encrypted_password
                    )
                    export_data.append(
                        {
                            "service": password_data.service,
                            "username": password_data.username,
                            "password": decrypted_password,
                            "notes": password_data.notes,
                            "created_at": password_data.created_at,
                            "updated_at": password_data.updated_at,
                        }
                    )
                except Exception as e:
                    logger.error(
                        f"Erro ao descriptografar senha {password_data.service}: {e}"
                    )

            with open(filename, "w", encoding="utf-8") as file:
                json.dump(export_data, file, indent=2, ensure_ascii=False)

            logger.info(f"Senhas exportadas para {filename}")
            return True, f"Senhas exportadas para {filename}"

        except Exception as e:
            logger.error(f"Erro ao exportar senhas: {e}")
            return False, f"Erro ao exportar: {str(e)}"


def main():
    """Função principal para teste do sistema melhorado."""
    print("🔐 Gerenciador de Senhas Melhorado - PyConsilium")
    print("=" * 60)
    print("🔑 Sistema com arquivo de chave mestra automático")
    print("=" * 60)

    try:
        # Inicializa gerenciador (sem senha - carrega do arquivo automaticamente)
        manager = ImprovedPasswordManager()
        print("✅ Gerenciador inicializado com sucesso!")

        # Menu de teste
        while True:
            print("\n" + "=" * 50)
            print("📋 MENU PRINCIPAL")
            print("=" * 50)
            print("1. ➕ Adicionar Senha")
            print("2. 🔍 Buscar Senha")
            print("3. 📊 Relatório de Força")
            print("4. 🔍 Buscar por Texto")
            print("5. 📤 Exportar Senhas")
            print("6. 🔑 Gerenciar Chave Mestra")
            print("7. ❌ Sair")
            print("-" * 50)

            choice = input("Escolha uma opção (1-7): ").strip()

            if choice == "1":
                service = input("Nome do serviço: ").strip()
                username = input("Nome de usuário: ").strip()
                password = getpass.getpass("Senha: ")
                notes = input("Notas (opcional): ").strip()

                success, message = manager.add_password(
                    service, username, password, notes
                )
                print(f"{'✅' if success else '❌'} {message}")

            elif choice == "2":
                service = input("Nome do serviço: ").strip()
                username = input("Nome de usuário: ").strip()

                password, message = manager.get_password(service, username)
                if password:
                    print(f"✅ {message}")
                    print(f"Senha: {password}")
                else:
                    print(f"❌ {message}")

            elif choice == "3":
                report = manager.get_strength_report()
                print(f"\n📊 RELATÓRIO DE FORÇA")
                print(f"Total de senhas: {report['total']}")
                print("\nDistribuição por força:")
                for level, count in report["strength_distribution"].items():
                    percentage = (
                        (count / report["total"]) * 100 if report["total"] > 0 else 0
                    )
                    print(f"  {level}: {count} ({percentage:.1f}%)")

                if report["weak_passwords"]:
                    print(f"\n⚠️ Senhas fracas ({len(report['weak_passwords'])}):")
                    for weak in report["weak_passwords"]:
                        print(
                            f"  • {weak['service']} - {weak['username']} (Score: {weak['score']})"
                        )

            elif choice == "4":
                query = input("Digite o texto para buscar: ").strip()
                results = manager.search_passwords(query)

                if results:
                    print(f"\n✅ {len(results)} senha(s) encontrada(s):")
                    for pwd in results:
                        print(f"  • {pwd.service} - {pwd.username}")
                else:
                    print("❌ Nenhuma senha encontrada")

            elif choice == "5":
                filename = input("Nome do arquivo (opcional): ").strip()
                success, message = manager.export_passwords(
                    filename if filename else None
                )
                print(f"{'✅' if success else '❌'} {message}")

            elif choice == "6":
                # Submenu de gerenciamento da chave mestra
                print("\n" + "=" * 40)
                print("🔑 GERENCIAMENTO DA CHAVE MESTRA")
                print("=" * 40)
                print("1. 💾 Criar Backup da Chave")
                print("2. 🔄 Regenerar Chave (PERIGOSO!)")
                print("3. 📋 Informações da Chave")
                print("4. ⬅️ Voltar ao Menu Principal")
                print("-" * 40)

                key_choice = input("Escolha uma opção (1-4): ").strip()

                if key_choice == "1":
                    success, message = manager.backup_key_file()
                    print(f"{'✅' if success else '❌'} {message}")

                elif key_choice == "2":
                    print(
                        "\n⚠️ ATENÇÃO: Regenerar a chave mestra tornará TODAS as senhas inacessíveis!"
                    )
                    confirm = input("Digite 'CONFIRMAR' para continuar: ").strip()
                    if confirm == "CONFIRMAR":
                        success, message = manager.regenerate_master_key()
                        print(f"{'✅' if success else '❌'} {message}")
                    else:
                        print("❌ Operação cancelada")

                elif key_choice == "3":
                    key_exists = manager.key_manager.key_exists()
                    print(f"\n📋 INFORMAÇÕES DA CHAVE MESTRA")
                    print(f"Arquivo existe: {'✅ Sim' if key_exists else '❌ Não'}")
                    if key_exists:
                        file_size = manager.key_manager.key_file.stat().st_size
                        print(f"Tamanho do arquivo: {file_size} bytes")
                        print(f"Caminho: {manager.key_manager.key_file}")
                        print(
                            f"Permissões: {oct(manager.key_manager.key_file.stat().st_mode)[-3:]}"
                        )

                elif key_choice == "4":
                    continue
                else:
                    print("❌ Opção inválida!")

            elif choice == "7":
                print("👋 Obrigado por usar o Gerenciador de Senhas!")
                break
            else:
                print("❌ Opção inválida!")

    except Exception as e:
        logger.error(f"Erro na aplicação: {e}")
        print(f"❌ Erro inesperado: {e}")


if __name__ == "__main__":
    main()
