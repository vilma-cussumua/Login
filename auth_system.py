"""
High-Performance Authentication System
Sistema de autenticação de alta performance com segurança robusta
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import bcrypt

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AuthStatus(Enum):
    """Status de autenticação"""
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    USER_LOCKED = "user_locked"
    SESSION_EXPIRED = "session_expired"
    INVALID_TOKEN = "invalid_token"
    FORBIDDEN = "forbidden"


@dataclass
class Session:
    """Representa uma sessão de usuário"""
    session_id: str
    user_id: str
    username: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    
    def is_valid(self) -> bool:
        """Verifica se a sessão ainda é válida"""
        return datetime.now() < self.expires_at
    
    def is_expired(self) -> bool:
        """Verifica se a sessão expirou"""
        return datetime.now() >= self.expires_at
    
    def update_activity(self):
        """Atualiza último tempo de atividade"""
        self.last_activity = datetime.now()


@dataclass
class User:
    """Representa um usuário"""
    user_id: str
    username: str
    email: str
    password_hash: str
    created_at: datetime
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    two_factor_enabled: bool = False
    
    def is_locked(self) -> bool:
        """Verifica se a conta está bloqueada"""
        if self.locked_until is None:
            return False
        return datetime.now() < self.locked_until


class HighPerformanceAuthSystem:
    """Sistema de autenticação de alta performance"""
    
    # Constantes de segurança
    MAX_LOGIN_ATTEMPTS = 5
    LOCK_DURATION_MINUTES = 30
    SESSION_TIMEOUT_MINUTES = 30
    TOKEN_EXPIRY_HOURS = 24
    SESSION_REFRESH_THRESHOLD_MINUTES = 5
    
    def __init__(self, max_workers: int = 10):
        """
        Inicializa o sistema de autenticação
        
        Args:
            max_workers: Número máximo de workers para processamento paralelo
        """
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.token_blacklist: set = set()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.lock = threading.RLock()
        logger.info("Sistema de autenticação inicializado")
    
    def _hash_password(self, password: str) -> str:
        """
        Hash de senha com bcrypt (seguro)
        
        Args:
            password: Senha em texto plano
            
        Returns:
            Hash da senha
        """
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verifica senha contra hash
        
        Args:
            password: Senha em texto plano
            password_hash: Hash armazenado
            
        Returns:
            True se a senha está correta
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.error(f"Erro ao verificar senha: {e}")
            return False
    
    def _generate_secure_token(self, length: int = 32) -> str:
        """
        Gera token criptograficamente seguro
        
        Args:
            length: Tamanho do token em bytes
            
        Returns:
            Token hexadecimal
        """
        return secrets.token_hex(length)
    
    def _generate_session_id(self, user_id: str, timestamp: float) -> str:
        """
        Gera ID de sessão único e seguro
        
        Args:
            user_id: ID do usuário
            timestamp: Timestamp atual
            
        Returns:
            Session ID
        """
        token = secrets.token_hex(16)
        data = f"{user_id}:{timestamp}:{token}".encode('utf-8')
        session_hash = hashlib.sha256(data).hexdigest()
        return session_hash
    
    def register_user(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """
        Registra um novo usuário
        
        Args:
            username: Nome de usuário
            email: Email do usuário
            password: Senha em texto plano
            
        Returns:
            Tupla (sucesso, mensagem)
        """
        with self.lock:
            # Validações
            if username in self.users:
                return False, "Usuário já existe"
            
            if len(password) < 8:
                return False, "Senha deve ter pelo menos 8 caracteres"
            
            if "@" not in email:
                return False, "Email inválido"
            
            # Criar novo usuário
            user_id = self._generate_secure_token(16)
            password_hash = self._hash_password(password)
            
            user = User(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                created_at=datetime.now()
            )
            
            self.users[username] = user
            logger.info(f"Usuário registrado: {username}")
            return True, "Usuário registrado com sucesso"
    
    def login(self, username: str, password: str, ip_address: str, 
              user_agent: str) -> Tuple[AuthStatus, Optional[Dict]]:
        """
        Realiza login de um usuário
        
        Args:
            username: Nome de usuário
            password: Senha em texto plano
            ip_address: Endereço IP do cliente
            user_agent: User agent do cliente
            
        Returns:
            Tupla (status, dados_sessão)
        """
        with self.lock:
            # Verificar se usuário existe
            if username not in self.users:
                logger.warning(f"Tentativa de login com usuário inexistente: {username}")
                return AuthStatus.INVALID_CREDENTIALS, None
            
            user = self.users[username]
            
            # Verificar se conta está bloqueada
            if user.is_locked():
                remaining_time = (user.locked_until - datetime.now()).total_seconds() / 60
                logger.warning(f"Conta bloqueada: {username} ({remaining_time:.0f} min restantes)")
                return AuthStatus.USER_LOCKED, None
            
            # Verificar senha
            if not self._verify_password(password, user.password_hash):
                user.failed_login_attempts += 1
                
                if user.failed_login_attempts >= self.MAX_LOGIN_ATTEMPTS:
                    user.locked_until = datetime.now() + timedelta(
                        minutes=self.LOCK_DURATION_MINUTES
                    )
                    logger.warning(f"Conta bloqueada por múltiplas tentativas: {username}")
                    return AuthStatus.USER_LOCKED, None
                
                logger.warning(f"Senha incorreta: {username} ({user.failed_login_attempts}/{self.MAX_LOGIN_ATTEMPTS})")
                return AuthStatus.INVALID_CREDENTIALS, None
            
            # Reset de tentativas falhadas
            user.failed_login_attempts = 0
            user.last_login = datetime.now()
            
            # Criar sessão
            session_id = self._generate_session_id(user.user_id, time.time())
            now = datetime.now()
            expires_at = now + timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
            
            session = Session(
                session_id=session_id,
                user_id=user.user_id,
                username=username,
                created_at=now,
                expires_at=expires_at,
                last_activity=now,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.sessions[session_id] = session
            
            # Gerar tokens
            access_token = self._generate_secure_token()
            refresh_token = self._generate_secure_token()
            
            logger.info(f"Login bem-sucedido: {username} from {ip_address}")
            
            return AuthStatus.SUCCESS, {
                "session_id": session_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user_id": user.user_id,
                "username": username,
                "expires_in": self.SESSION_TIMEOUT_MINUTES * 60,
                "created_at": now.isoformat()
            }
    
    def validate_session(self, session_id: str) -> Tuple[bool, Optional[Session]]:
        """
        Valida uma sessão ativa
        
        Args:
            session_id: ID da sessão
            
        Returns:
            Tupla (válida, sessão)
        """
        with self.lock:
            if session_id not in self.sessions:
                return False, None
            
            session = self.sessions[session_id]
            
            if not session.is_valid():
                del self.sessions[session_id]
                logger.info(f"Sessão expirada removida: {session_id}")
                return False, None
            
            # Atualizar última atividade
            session.update_activity()
            return True, session
    
    def refresh_session(self, session_id: str) -> Tuple[bool, Optional[Dict]]:
        """
        Renova uma sessão
        
        Args:
            session_id: ID da sessão
            
        Returns:
            Tupla (sucesso, novos_tokens)
        """
        with self.lock:
            valid, session = self.validate_session(session_id)
            
            if not valid:
                return False, None
            
            # Renovar expiração
            old_expires = session.expires_at
            session.expires_at = datetime.now() + timedelta(
                minutes=self.SESSION_TIMEOUT_MINUTES
            )
            
            # Novos tokens
            access_token = self._generate_secure_token()
            refresh_token = self._generate_secure_token()
            
            logger.info(f"Sessão renovada: {session_id}")
            
            return True, {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": self.SESSION_TIMEOUT_MINUTES * 60,
                "old_expires": old_expires.isoformat(),
                "new_expires": session.expires_at.isoformat()
            }
    
    def logout(self, session_id: str) -> Tuple[bool, str]:
        """
        Realiza logout de um usuário
        
        Args:
            session_id: ID da sessão
            
        Returns:
            Tupla (sucesso, mensagem)
        """
        with self.lock:
            if session_id not in self.sessions:
                return False, "Sessão não encontrada"
            
            session = self.sessions[session_id]
            username = session.username
            
            del self.sessions[session_id]
            
            # Adicionar à blacklist para invalidar tokens
            self.token_blacklist.add(session_id)
            
            logger.info(f"Logout bem-sucedido: {username}")
            return True, "Logout realizado com sucesso"
    
    def logout_all_sessions(self, username: str) -> Tuple[bool, int]:
        """
        Faz logout de todas as sessões de um usuário
        
        Args:
            username: Nome do usuário
            
        Returns:
            Tupla (sucesso, quantidade de sessões encerradas)
        """
        with self.lock:
            sessions_to_remove = [
                sid for sid, session in self.sessions.items()
                if session.username == username
            ]
            
            for session_id in sessions_to_remove:
                del self.sessions[session_id]
                self.token_blacklist.add(session_id)
            
            logger.info(f"Todas as sessões encerradas: {username} ({len(sessions_to_remove)} sessões)")
            return True, len(sessions_to_remove)
    
    def get_active_sessions(self, username: str) -> list:
        """
        Obtém todas as sessões ativas de um usuário
        
        Args:
            username: Nome do usuário
            
        Returns:
            Lista de sessões ativas
        """
        with self.lock:
            active_sessions = []
            for session_id, session in self.sessions.items():
                if session.username == username and session.is_valid():
                    active_sessions.append({
                        "session_id": session_id,
                        "created_at": session.created_at.isoformat(),
                        "expires_at": session.expires_at.isoformat(),
                        "last_activity": session.last_activity.isoformat(),
                        "ip_address": session.ip_address,
                        "user_agent": session.user_agent
                    })
            
            return active_sessions
    
    def cleanup_expired_sessions(self):
        """Remove sessões expiradas do sistema"""
        with self.lock:
            expired_sessions = [
                sid for sid, session in self.sessions.items()
                if session.is_expired()
            ]
            
            for session_id in expired_sessions:
                del self.sessions[session_id]
            
            if expired_sessions:
                logger.info(f"Limpeza de sessões: {len(expired_sessions)} sessões removidas")
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Obtém informações do usuário
        
        Args:
            username: Nome do usuário
            
        Returns:
            Dicionário com informações do usuário
        """
        with self.lock:
            if username not in self.users:
                return None
            
            user = self.users[username]
            return {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "is_locked": user.is_locked(),
                "two_factor_enabled": user.two_factor_enabled
            }


# Exemplo de uso
if __name__ == "__main__":
    # Inicializar sistema
    auth_system = HighPerformanceAuthSystem(max_workers=10)
    
    print("=" * 60)
    print("SISTEMA DE AUTENTICAÇÃO DE ALTA PERFORMANCE")
    print("=" * 60)
    
    # 1. Registrar usuários
    print("\n[1] Registrando usuários...")
    auth_system.register_user("joao_silva", "joao@example.com", "senha_segura_123")
    auth_system.register_user("maria_santos", "maria@example.com", "outra_senha_456")
    print("✓ Usuários registrados")
    
    # 2. Login bem-sucedido
    print("\n[2] Realizando login...")
    status, session_data = auth_system.login(
        username="joao_silva",
        password="senha_segura_123",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0"
    )
    
    if status == AuthStatus.SUCCESS:
        print(f"✓ Login bem-sucedido!")
        print(f"  Session ID: {session_data['session_id'][:16]}...")
        print(f"  Access Token: {session_data['access_token'][:16]}...")
        print(f"  Expira em: {session_data['expires_in']} segundos")
        session_id = session_data['session_id']
    else:
        print(f"✗ Falha no login: {status.value}")
    
    # 3. Validar sessão
    print("\n[3] Validando sessão...")
    is_valid, session = auth_system.validate_session(session_id)
    print(f"✓ Sessão válida: {is_valid}")
    
    # 4. Ver informações do usuário
    print("\n[4] Informações do usuário...")
    user_info = auth_system.get_user_info("joao_silva")
    print(f"  Username: {user_info['username']}")
    print(f"  Email: {user_info['email']}")
    print(f"  Criado em: {user_info['created_at']}")
    print(f"  Último login: {user_info['last_login']}")
    
    # 5. Ver sessões ativas
    print("\n[5] Sessões ativas...")
    active_sessions = auth_system.get_active_sessions("joao_silva")
    print(f"  Total: {len(active_sessions)} sessão(ões)")
    for sess in active_sessions:
        print(f"  - IP: {sess['ip_address']} | Criada: {sess['created_at']}")
    
    # 6. Renovar sessão
    print("\n[6] Renovando sessão...")
    success, new_tokens = auth_system.refresh_session(session_id)
    if success:
        print(f"✓ Sessão renovada")
        print(f"  Novo Token: {new_tokens['access_token'][:16]}...")
    
    # 7. Logout
    print("\n[7] Realizando logout...")
    success, message = auth_system.logout(session_id)
    print(f"✓ {message}")
    
    # 8. Validar sessão após logout
    print("\n[8] Validando sessão após logout...")
    is_valid, session = auth_system.validate_session(session_id)
    print(f"✓ Sessão válida: {is_valid}")
    
    # 9. Tentativa de login com senha incorreta
    print("\n[9] Tentando login com senha incorreta...")
    for i in range(6):
        status, _ = auth_system.login(
            username="joao_silva",
            password="senha_incorreta",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        print(f"  Tentativa {i+1}: {status.value}")
        if status == AuthStatus.USER_LOCKED:
            print("  → Conta bloqueada por segurança!")
            break
    
    print("\n" + "=" * 60)
    print("TESTE CONCLUÍDO")
    print("=" * 60)
