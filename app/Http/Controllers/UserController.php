<?php

namespace App\Http\Controllers;

use App\Mail\AccountCreatedMail;
use App\Mail\AccountBlockedMail;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $user = User::create([
        ]);

        Mail::to($user->email)->send(new AccountCreatedMail($user));

        return response()->json(['message' => 'Użytkownik zarejestrowany i mail wysłany.']);
    }

    public function blockAccount(User $user)
    {
        $user->update(['is_blocked' => true]);

        $user->reset_token = Str::random(60);
        $user->save();

        Mail::to($user->email)->send(new AccountBlockedMail($user));

        return response()->json(['message' => 'Konto zablokowane i mail wysłany.']);
    }
}
