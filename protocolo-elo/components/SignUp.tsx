import React, { useState, useMemo } from 'react';
import { firebaseService } from '../services/firebaseService';
import UserIcon from './icons/UserIcon';
import MailIcon from './icons/MailIcon';
import LockIcon from './icons/LockIcon';
import PhoneIcon from './icons/PhoneIcon';
import CheckCircleIcon from './icons/CheckCircleIcon';
import XCircleIcon from './icons/XCircleIcon';
import EyeIcon from './icons/EyeIcon';
import EyeOffIcon from './icons/EyeOffIcon';


interface SignUpProps {
    onSwitchToLogin: () => void;
}

const PasswordRequirement: React.FC<{ isValid: boolean; text: string }> = ({ isValid, text }) => (
    <div className={`flex items-center text-xs ${isValid ? 'text-green-400' : 'text-gray-400'}`}>
        {isValid ? <CheckCircleIcon className="w-4 h-4 mr-1" /> : <XCircleIcon className="w-4 h-4 mr-1" />}
        {text}
    </div>
);

const SignUp: React.FC<SignUpProps> = ({ onSwitchToLogin }) => {
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        recovery: '',
        password: '',
        confirmPassword: '',
    });
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [showSuccessMessage, setShowSuccessMessage] = useState(false);
    const [isPasswordVisible, setIsPasswordVisible] = useState(false);
    const [isConfirmPasswordVisible, setIsConfirmPasswordVisible] = useState(false);

    const {
        has8Chars,
        hasLowercase,
        hasUppercase,
        hasNumber,
        hasSpecialChar
    } = useMemo(() => {
        const password = formData.password;
        return {
            has8Chars: password.length >= 8,
            hasLowercase: /[a-z]/.test(password),
            hasUppercase: /[A-Z]/.test(password),
            hasNumber: /\d/.test(password),
            hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password),
        };
    }, [formData.password]);

    const isPasswordValid = has8Chars && hasLowercase && hasUppercase && hasNumber && hasSpecialChar;

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (!isPasswordValid) {
            setError('A senha não atende a todos os requisitos.');
            return;
        }

        if (formData.password !== formData.confirmPassword) {
            setError('As senhas não coincidem.');
            return;
        }

        setIsLoading(true);
        try {
            const recoveryIsEmail = formData.recovery.includes('@');
            await firebaseService.registerUser({
                username: formData.username,
                email: formData.email,
                password: formData.password,
                recoveryEmail: recoveryIsEmail ? formData.recovery : undefined,
                recoveryPhone: !recoveryIsEmail && formData.recovery ? formData.recovery : undefined,
            });
            setShowSuccessMessage(true);
        } catch (err: any) {
            setError(err.message || 'Ocorreu um erro durante o cadastro.');
        } finally {
            setIsLoading(false);
        }
    };
    
    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white p-4">
            <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
                {showSuccessMessage ? (
                     <div className="text-center">
                        <h1 className="text-2xl font-bold text-teal-400 mb-4">Cadastro Realizado!</h1>
                        <p className="text-gray-300 mb-6">Enviamos um link de confirmação para o seu e-mail. Por favor, verifique sua caixa de entrada (e a de spam) para ativar sua conta.</p>
                        <p className="text-gray-400 text-sm mb-6">(Para esta simulação, verifique o console do navegador para o seu token de confirmação).</p>
                        <button onClick={onSwitchToLogin} className="w-full px-4 py-2 font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700">
                            Ir para o Login
                        </button>
                    </div>
                ) : (
                <>
                <h1 className="text-3xl font-bold text-center text-teal-400">Criar Conta</h1>
                
                <div className="flex flex-col space-y-2">
                     <button disabled className="w-full py-2 font-semibold text-white bg-gray-600 rounded-md cursor-not-allowed flex items-center justify-center" title="Em breve">
                        Cadastrar com Google
                    </button>
                </div>
                <div className="flex items-center text-center">
                    <hr className="flex-grow border-gray-600" />
                    <span className="px-4 text-gray-400">OU</span>
                    <hr className="flex-grow border-gray-600" />
                </div>

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="relative">
                        <UserIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input name="username" type="text" value={formData.username} onChange={handleChange} required placeholder="Nome de usuário" className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    </div>
                    <div className="relative">
                         <MailIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input name="email" type="email" value={formData.email} onChange={handleChange} required placeholder="E-mail" className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    </div>
                    <div className="relative">
                        <PhoneIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input name="recovery" type="text" value={formData.recovery} onChange={handleChange} placeholder="E-mail ou Telefone de Recuperação (Opcional)" className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    </div>
                    <div className="relative">
                        <LockIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input name="password" type={isPasswordVisible ? 'text' : 'password'} value={formData.password} onChange={handleChange} required placeholder="Senha" className="w-full pl-10 pr-10 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <button type="button" onClick={() => setIsPasswordVisible(!isPasswordVisible)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white">
                            {isPasswordVisible ? <EyeOffIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
                        </button>
                    </div>

                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 pl-2">
                        <PasswordRequirement isValid={has8Chars} text="8+ caracteres" />
                        <PasswordRequirement isValid={hasLowercase} text="1 minúscula" />
                        <PasswordRequirement isValid={hasUppercase} text="1 maiúscula" />
                        <PasswordRequirement isValid={hasNumber} text="1 número" />
                        <PasswordRequirement isValid={hasSpecialChar} text="1 caractere especial" />
                    </div>

                    <div className="relative">
                        <LockIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                        <input name="confirmPassword" type={isConfirmPasswordVisible ? 'text' : 'password'} value={formData.confirmPassword} onChange={handleChange} required placeholder="Confirmar Senha" className="w-full pl-10 pr-10 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-teal-500" />
                         <button type="button" onClick={() => setIsConfirmPasswordVisible(!isConfirmPasswordVisible)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white">
                            {isConfirmPasswordVisible ? <EyeOffIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
                        </button>
                    </div>

                    {error && <p className="text-sm text-red-500 text-center">{error}</p>}
                    <button type="submit" disabled={isLoading} className="w-full px-4 py-2 font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed">
                        {isLoading ? 'Criando conta...' : 'Cadastrar'}
                    </button>
                </form>
                 <p className="text-sm text-center text-gray-400">
                    Já tem uma conta?{' '}
                    <button onClick={onSwitchToLogin} className="font-medium text-teal-400 hover:underline">
                        Entrar
                    </button>
                </p>
                </>
                )}
            </div>
        </div>
    );
};

export default SignUp;