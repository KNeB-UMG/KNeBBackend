<?php
// routes/api.php

use App\Http\Controllers\TechnicalController;
use App\Http\Controllers\MemberController;
use Illuminate\Support\Facades\Route;

Route::get('/technical/basic', [TechnicalController::class, 'getBasic']);

Route::prefix('/member')->group(function () {
    Route::post('/register', [MemberController::class, 'registerMember']);
    Route::post('/login', [MemberController::class, 'loginMember']);

    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/edit', [MemberController::class, 'editMember']);

        Route::middleware('role:role_admin')->group(function () {
            Route::post('/deactivate', [MemberController::class, 'deactivateMember']);
            Route::post('/delete', [MemberController::class, 'deleteMember']);
            Route::post('/activate', [MemberController::class, 'activateMember']);
            Route::post('/changerole', [MemberController::class, 'changeRoleOfMember']);
        });
    });
});
