<?php // routes/api.php

use App\Http\Controllers\TechnicalController;
use App\Http\Controllers\MemberController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\FileController;
use Illuminate\Support\Facades\Route;

Route::get('/technical/basic', [TechnicalController::class, 'getBasic']);

Route::prefix('/member')->group(function () {
    Route::post('/register', [MemberController::class, 'registerMember']);
    Route::post('/activate/{id}', [MemberController::class, 'activateAccount']);

    Route::post('/login', [MemberController::class, 'loginMember']);
    Route::middleware('auth:sanctum')->post('/profile-picture', [MemberController::class, 'uploadProfilePicture']);
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/edit', [MemberController::class, 'editMember']);
        Route::post('/deactivate', [MemberController::class, 'deactivateOwnAccount']);

        // Profile photo endpoints
        Route::post('/profile/upload-photo', [ProfileController::class, 'uploadProfilePhoto']);

        Route::middleware('role:role_admin')->group(function () {
            Route::post('/create', [MemberController::class, 'createMember']);
            Route::post('/{id}/deactivate', [MemberController::class, 'deactivateAccount']);
            Route::post('/{id}/delete', [MemberController::class, 'deleteMember']);
            Route::post('/{id}/activate', [MemberController::class, 'activateMember']);
            Route::post('/{id}/changerole', [MemberController::class, 'changeRole']);
            Route::put('/{id}/visibility', [MemberController::class, 'changeVisibility']);
            Route::put('/{id}/position', [MemberController::class, 'updatePosition']);
        });
    });
});

// File endpoints
Route::prefix('/files')->group(function () {
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/upload', [FileController::class, 'upload']);
    });

    // Public access to download files
    Route::get('/{id}', [FileController::class, 'download']);
});

// Public access to profile photos
Route::get('/profile/photo/{id}', [ProfileController::class, 'getProfilePhoto']);
