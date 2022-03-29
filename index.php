<?php
session_start();

require __DIR__.'/vendor/autoload.php';

use Kreait\Firebase\Auth\UserRecord;
use Kreait\Firebase\Request\CreateUser;
use Kreait\Firebase\Factory as FirebaseFactory;
use Kreait\Firebase\Exception\Auth\UserNotFound;
use Kreait\Firebase\Exception\FirebaseException;
use Kreait\Firebase\Exception\Auth\FailedToVerifyToken;

$firebase = (new FirebaseFactory)
    ->withServiceAccount('php-firebase-7e64d-firebase-adminsdk-nr0l6-e032a3e09c.json')
    ->withDatabaseUri('https://php-firebase-7e64d-default-rtdb.firebaseio.com/');

$database = $firebase->createDatabase();
$auth = $firebase->createAuth();
$msg = '';
$action = '';

if(!empty($_SESSION['user_token'])){
    try {
        $verifiedIdToken = $auth->verifyIdToken($_SESSION['user_token']);
    } catch (FailedToVerifyToken $e) {
        $action = 'logout';
    }
}

if ((isset($_GET['action']) && $_GET['action'] == 'logout') || (isset($action) && $action == 'logout')) {
    session_destroy();
    header("Location: index.php");
}

if (isset($_POST['action']) && $_POST['action'] == 'signup') {
    $email = $_POST['email'];
    $password = $_POST['password'];
    $repeatedPassword = $_POST['repeated_password'];

    if ($password === $repeatedPassword) {
        $request = CreateUser::new()
            ->withUnverifiedEmail($email)
            ->withClearTextPassword($password)
            ->markAsEnabled();

        try {
            $user = $auth->createUser($request);

            if ($user instanceof UserRecord) {
                $msg = 'Votre compte a été créé avec succès';
            }
        } catch (FirebaseException $e) {
            $msg = $e->getMessage();
        }

    }else {
        $msg = 'les mots de passe ne correspondent pas';
    }
}elseif (isset($_POST['action']) && $_POST['action'] == 'signin') {
    $email = $_POST['email'];
    $clearTextPassword = $_POST['password'];

    try {
        $user = $auth->getUserByEmail($email);

        try {
            $signInResult = $auth->signInWithEmailAndPassword($email, $clearTextPassword);
            $idToken = $signInResult->idToken();

            try {
                $verifiedIdToken = $auth->verifyIdToken($idToken);
                $uid = $verifiedIdToken->claims()->get('sub');

                $_SESSION['connected'] = true;
                $_SESSION['user_id'] = $uid;
                $_SESSION['user_token'] = $idToken;

                $msg = 'Vous êtes connecté';

            } catch (FailedToVerifyToken $e) {
                $msg = 'Le jeton d\'authentification est invalide';
            }

        } catch (\InvalidArgumentException $e) {
            $msg = 'Le jeton d\'authentification ne peut etre parser';
        }

    } catch (UserNotFound $e) {
        $msg = 'L\'email n\'existe pas';
    }
}


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firebase Authentication</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
</head>
<body>
    <div class="container">
        <?php if (isset($_SESSION['connected']) && $_SESSION['connected']): ?>
            <h1>Salutations x! Vous étes connecté</h1>
            <a href="index.php?action=logout">Se déconnecter</a>
        <?php else: ?>
            <h1 class="text-center mb-2">Authentication</h1>
            
            <hr>
            <div class="row mb-2">
                <div class="col-lg-5 mx-auto">
                    <form method="post" class="card shadow-sm p-3">
                        <div class="h4 text-center">Inscription</div>
                        <div class="row">
                            <div class="col-12 mb-1">
                                <input required type="email" class="form-control" placeholder="Votre email" name="email">
                            </div>
                            <div class="col-12 mb-1">
                                <input required type="password" class="form-control" placeholder="Votre mot de passe" name="password">
                            </div>
                            <div class="col-12 mb-1">
                                <input required type="password" class="form-control" placeholder="Votre mot de passe" name="repeated_password">
                            </div>
                            <div class="col-12 mb-1">
                                <button class="btn btn-primary d-block" type="submit">S'inscrire</button>
                            </div>
                        </div>
                        <input required type="hidden" name="action" value="signup">
                    </form>
                </div>
                <div class="col-lg-5 mx-auto">
                    <form method="post" class="card shadow-sm p-3">
                        <div class="h4 text-center">Connexion</div>
                        <div class="row">
                            <div class="col-12 mb-1">
                                <input required type="email" class="form-control" name="email" placeholder="Votre email" >
                            </div>
                            <div class="col-12 mb-1">
                                <input required type="password" class="form-control" name="password" placeholder="Votre mot de passe" >
                            </div>
                            <div class="col-12 mb-1">
                                <button class="btn btn-primary d-block" type="submit">Se connecter</button>
                            </div>
                        </div>
                        <input required type="hidden" name="action" value="signin">
                    </form>
                </div>
            </div>
            <p class="text-center"><?= $msg; ?></p>
        <?php endif ?>
    </div>


    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.10.2/dist/umd/popper.min.js" integrity="sha384-7+zCNj/IqJ95wo16oMtfsKbZ9ccEh31eOz1HGyDuCQ6wgnyJNSYdrPa03rtR1zdB" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js" integrity="sha384-QJHtvGhmr9XOIpI6YVutG+2QOK9T+ZnN4kzFN1RtK3zEFEIsxhlmWl5/YESvpZ13" crossorigin="anonymous"></script>
</body>
</html>