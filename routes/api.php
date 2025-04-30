<?php

use App\Http\Controllers\EventController;
use App\Http\Controllers\PostController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\MemberController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Public routes
Route::get('/members/all', [MemberController::class, 'getAllPublicMembers']);

// Member routes
Route::prefix('/member')->group(function () {
    // Public member routes
    Route::post('/register', [MemberController::class, 'registerMember']);
    Route::post('/activate/{code}', [MemberController::class, 'activateAccount']);
    Route::post('/login', [MemberController::class, 'loginMember']);
    Route::post('/request-password-reset', [MemberController::class, 'requestPasswordReset']);
    Route::post('/reset-password', [MemberController::class, 'resetPassword']);

    // Protected member routes
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/profile-picture', [MemberController::class, 'uploadProfilePicture']);
        Route::put('/edit', [MemberController::class, 'editMember']);
        Route::post('/deactivate', [MemberController::class, 'deactivateOwnAccount']);
    });
});

// Admin routes
Route::prefix('admin/member')->middleware('auth:sanctum')->group(function () {
    Route::post('/create', [MemberController::class, 'createMember']);
    Route::post('/{id}/deactivate', [MemberController::class, 'deactivateAccount']);
    Route::put('/{id}/role', [MemberController::class, 'changeRole']);
    Route::put('/{id}/visibility', [MemberController::class, 'changeVisibility']);
    Route::put('/{id}/position', [MemberController::class, 'updatePosition']);
    Route::put('/{id}/edit', [MemberController::class, 'adminEditMember']);
});


Route::get('/events', [EventController::class, 'index']);
Route::get('/events/{path}', [EventController::class, 'show']);

// Protected event routes
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/events', [EventController::class, 'store']);
    Route::put('/events/{id}', [EventController::class, 'update']);
    Route::delete('/events/{id}', [EventController::class, 'destroy']);
});

// Admin event routes
Route::prefix('admin/events')->middleware('auth:sanctum')->group(function () {
    Route::get('/', [EventController::class, 'adminIndex']);
    Route::get('/{id}', [EventController::class, 'adminShow']);
    Route::put('/{id}/visibility', [EventController::class, 'updateVisibility']);
});
// Posts routes
Route::prefix('posts')->group(function () {
    Route::get('/', [PostController::class, 'regularPosts']);
    Route::get('/super_events', [PostController::class, 'superEvents']);

    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/store', [PostController::class, 'store']);
        Route::put('/{id}', [PostController::class, 'update']);
    });
});
Route::prefix('admin/posts')->middleware('auth:sanctum')->group(function () {
    Route::put('/{id}/update-status', [PostController::class, 'updateStatus']);
});
