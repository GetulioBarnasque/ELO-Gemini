import React, { useState } from 'react';
import { firebaseService } from '../services/firebaseService';
import { PublicUser } from '../types';
import SignUp from './SignUp';
import MailIcon from './icons/MailIcon';
import LockIcon from './icons/LockIcon';
import KeyIcon from './icons/KeyIcon';
import EyeIcon from './icons/EyeIcon';
import EyeOffIcon from './icons/EyeOffIcon';

interface LoginProps {
  onLogin: (user: PublicUser) => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [view, setView] = useState<'login' | 'signup' | 'confirm' | 'forgot-password' | 'reset-password'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const [confirmToken, setConfirmToken] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [isNewPasswordVisible, setIsNewPasswordVisible] = useState(false);
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [isConfirmNewPasswordVisible, setIsConfirmNewPasswordVisible] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // Clear fields and messages when view changes
  const switchView = (newView: typeof view) => {
      setError('');
      setMessage('');
      // FIX: Do not clear email when switching views, as it might be needed.
      setPassword('');
      setConfirmToken('');
      setResetToken('');
      setNewPassword('');
      setConfirmNewPassword('');
      setView(newView);
  }

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setIsLoading(true);
    try {
      const user = await firebaseService.login(email, password);
      onLogin(user);
    } catch (err: any) {
        if (err.message === 'EMAIL_NOT_VERIFIED') {
            setError('Seu e-mail ainda não foi verificado. Por favor, confirme sua conta.');
        } else {
            setError(err.message || 'Ocorreu um erro durante o login.');
        }
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirmSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setIsLoading(true);
    try {
        const success = await firebaseService.confirmEmail(confirmToken);
        if (success) {
            setMessage('E-mail confirmado com sucesso! Agora você pode fazer o login.');
            setConfirmToken('');
            setView('login');
        } else {
            setError('Token de confirmação inválido ou expirado.');
        }
    } catch (err: any) {
        setError(err.message || 'Ocorreu um erro durante a confirmação.');
    } finally {
        setIsLoading(false);
    }
  };

  const handleForgotPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setIsLoading(true);
    try {
        await firebaseService.requestPasswordReset(email);
        setMessage('Se o e-mail estiver cadastrado, um link de recuperação foi enviado. Verifique o console do seu navegador para obter o token.');
    } catch (err: any) {
        setError(err.message || 'Ocorreu um erro.');
    } finally {
        setIsLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (newPassword !== confirmNewPassword) {
        setError('As novas senhas não coincidem.');
        return;
    }

    setIsLoading(true);
    try {
        const success = await firebaseService.resetPassword(resetToken, newPassword);
        if (success) {
            setMessage('Senha redefinida com sucesso! Você já pode fazer o login com a nova senha.');
            setResetToken('');
            setNewPassword('');
            setConfirmNewPassword('');
            switchView('login');
        } else {
            setError('Token de recuperação inválido ou expirado. Por favor, solicite um novo.');
        }
    } catch (err: any) {
        setError(err.message || 'Ocorreu um erro ao redefinir a senha.');
    } finally {
        setIsLoading(false);
    }
  };

  if (view === 'signup') {
    return <SignUp onSwitchToLogin={() => switchView('login')} />;
  }

  return (
    <div className="flex items-center justify-center h-screen bg-gray-900 text-white">
      <div className="w-full max-w-sm p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
        <h1 className="text-3xl font-bold text-center text-teal-400">Protocolo ELO</h1>
        
        {view === 'login' && (
            <>
            <p className="text-center text-gray-400">Faça login para continuar</p>
            <form onSubmit={handleLoginSubmit} className="space-y-4">
                <div className="relative">
                    <MailIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input id="email" name="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full px-4 py-2 pl-10 bg-gray-700 border border-gray-600 rounded-md placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500" placeholder="E-mail" />
                </div>
                <div className="relative">
                    <LockIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input id="password" name="password" type={isPasswordVisible ? 'text' : 'password'} required value={password} onChange={(e) => setPassword(e.target.value)} className="w-full px-4 py-2 pl-10 pr-10 bg-gray-700 border border-gray-600 rounded-md placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500" placeholder="Senha" />
                    <button type="button" onClick={() => setIsPasswordVisible(!isPasswordVisible)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white">
                        {isPasswordVisible ? <EyeOffIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
                    </button>
                </div>
                <div className="text-right text-sm">
                    <button type="button" onClick={() => switchView('forgot-password')} className="font-medium text-teal-400 hover:underline">
                        Esqueceu a senha?
                    </button>
                </div>
                {error && <p className="text-sm text-red-500 text-center">{error}</p>}
                {message && <p className="text-sm text-green-500 text-center">{message}</p>}
                <button type="submit" disabled={isLoading} className="w-full px-4 py-2 font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-teal-500">
                    {isLoading ? 'Entrando...' : 'Entrar'}
                </button>
            </form>
            <div className="text-sm text-center text-gray-400">
                <button onClick={() => switchView('confirm')} className="font-medium text-teal-400 hover:underline">Confirmar E-mail</button>
            </div>
            <p className="text-sm text-center text-gray-400">
                Não tem uma conta?{' '}
                <button onClick={() => switchView('signup')} className="font-medium text-teal-400 hover:underline">
                Cadastre-se
                </button>
            </p>
            </>
        )}

        {view === 'confirm' && (
             <>
                <p className="text-center text-gray-400">Confirme sua conta</p>
                <form onSubmit={handleConfirmSubmit} className="space-y-4">
                    <div className="relative">
                        <KeyIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input id="token" name="token" type="text" required value={confirmToken} onChange={(e) => setConfirmToken(e.target.value)} className="w-full px-4 py-2 pl-10 bg-gray-700 border border-gray-600 rounded-md placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500" placeholder="Token de Confirmação" />
                    </div>
                    {error && <p className="text-sm text-red-500 text-center">{error}</p>}
                    <button type="submit" disabled={isLoading} className="w-full px-4 py-2 font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed">
                        {isLoading ? 'Confirmando...' : 'Confirmar'}
                    </button>
                </form>
                <p className="text-sm text-center text-gray-400">
                    <button onClick={() => switchView('login')} className="font-medium text-teal-400 hover:underline">
                        Voltar para o Login
                    </button>
                </p>
            </>
        )}

        {view === 'forgot-password' && (
            <>
                <p className="text-center text-gray-400">Recuperar Senha</p>
                <form onSubmit={handleForgotPasswordSubmit} className="space-y-4">
                    <div className="relative">
                        <MailIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input id="email" name="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full px-4 py-2 pl-10 bg-gray-700 border border-gray-600 rounded-md placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500" placeholder="Seu e-mail cadastrado" />
                    </div>
                    {error && <p className="text-sm text-red-500 text-center">{error}</p>}
                    {message && <p className="text-sm text-green-500 text-center">{message}</p>}
                    <button type="submit" disabled={isLoading} className="w-full px-4 py-2 font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed">
                        {isLoading ? 'Enviando...' : 'Enviar Link de Recuperação'}
                    </button>
                </form>
                <div className="text-sm text-center text-gray-400 space-x-4">
                    <button onClick={() => switchView('reset-password')} className="font-medium text-teal-400 hover:underline">Redefinir Senha</button>
                     <span className="text-gray-600">|</span>
                    <button onClick={() => switchView('login')} className="font-medium text-teal-400 hover:underline">Fazer Login</button>
                </div>
            </>
        )}

        {view === 'reset-password' && (
            <>
                <p className="text-center text-gray-400">Redefinir Senha</p>
                <form onSubmit={handleResetPasswordSubmit} className="space-y-4">
                    <div className="relative">
                        <KeyIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input id="resetToken" name="resetToken" type="text" required value={resetToken} onChange={(e) => setResetToken(e.target.value)} className="w-full px-4 py-2 pl-10 bg-gray-700 border border-gray-600 rounded-md placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500" placeholder="Token de Recuperação" />
                    </div>
                    <div className="relative">
                        <LockIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input id="newPassword" name="newPassword" type={isNewPasswordVisible ? 'text' : 'password'} required value={newPassword} onChange={(e) => setNewPassword(e.target.value)} className="w-full px-4 py-2 pl-10 pr-10 bg-gray-700 border border-gray-600 rounded-md placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500" placeholder="Nova Senha" />
                        <button type="button" onClick={() => setIsNewPasswordVisible(!isNewPasswordVisible)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white">
                            {isNewPasswordVisible ? <EyeOffIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
                        </button>
                    </div>
                    <div className="relative">
                        <LockIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input id="confirmNewPassword" name="confirmNewPassword" type={isConfirmNewPasswordVisible ? 'text' : 'password'} required value={confirmNewPassword} onChange={(e) => setConfirmNewPassword(e.target.value)} className="w-full px-4 py-2 pl-10 pr-10 bg-gray-700 border border-gray-600 rounded-md placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500" placeholder="Confirmar Nova Senha" />
                        <button type="button" onClick={() => setIsConfirmNewPasswordVisible(!isConfirmNewPasswordVisible)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white">
                            {isConfirmNewPasswordVisible ? <EyeOffIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
                        </button>
                    </div>
                    
                    {error && <p className="text-sm text-red-500 text-center">{error}</p>}
                    {message && <p className="text-sm text-green-500 text-center">{message}</p>}

                    <button type="submit" disabled={isLoading} className="w-full px-4 py-2 font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed">
                        {isLoading ? 'Redefinindo...' : 'Redefinir Senha'}
                    </button>
                </form>
                <p className="text-sm text-center text-gray-400">
                    <button onClick={() => switchView('login')} className="font-medium text-teal-400 hover:underline">
                        Voltar para o Login
                    </button>
                </p>
            </>
        )}

      </div>
    </div>
  );
};

export default Login;