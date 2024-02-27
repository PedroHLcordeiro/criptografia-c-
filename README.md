# criptografia-c#
Install-Package BCrypt.Net-Next
using System;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        // Exemplo de registro de usuário
        string senhaDoUsuario = "senha123";

        // Gere um hash seguro da senha antes de armazená-la no banco de dados
        string hashDaSenha = HashSenha(senhaDoUsuario);

        // Armazene o hashDaSenha no banco de dados junto com outros detalhes do usuário
        Console.WriteLine("Hash da senha: " + hashDaSenha);

        // Exemplo de login
        string senhaDeLogin = "senha123";

        // Verifique se a senha inserida durante o login corresponde ao hash armazenado no banco de dados
        bool senhaCorreta = VerificarSenha(senhaDeLogin, hashDaSenha);

        if (senhaCorreta)
        {
            Console.WriteLine("Login bem-sucedido!");
        }
        else
        {
            Console.WriteLine("Senha incorreta. Tente novamente.");
        }
    }

    static string HashSenha(string senha)
    {
        // Gere um salt aleatório
        byte[] salt;
        new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);

        // Configure o parâmetro de custo para o algoritmo bcrypt
        int custo = 12; // Ajuste conforme necessário (maior custo = mais lento, mais seguro)

        // Gere o hash usando bcrypt
        string hashSenha = BCrypt.Net.BCrypt.HashPassword(senha, BCrypt.Net.BCrypt.GenerateSalt(custo));

        return hashSenha;
    }

    static bool VerificarSenha(string senha, string hashArmazenado)
    {
        // Verifique se a senha inserida corresponde ao hash armazenado usando bcrypt
        return BCrypt.Net.BCrypt.Verify(senha, hashArmazenado);
    }
}
