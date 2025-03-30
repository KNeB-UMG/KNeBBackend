<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Zmiana hasła</title>
</head>
<body>
<h1>Uwaga, {{ $user->name }}!</h1>
<p>Twoje konto zostało zablokowane. Aby je odblokować, prosimy o zmianę hasła. Kliknij poniższy link:</p>
<p><a href="{{ route('password.reset', ['token' => $user->reset_token]) }}">Resetuj hasło</a></p>
</body>
</html>
