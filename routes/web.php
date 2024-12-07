<?php

use App\Http\Controllers\TechnicalController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});
Route::get('api/technical/basic', [TechnicalController::class, 'getBasic']);
// routes for managing user
Route::prefix('api/member')->name('api/member.')->group(function () {
    Route::post('/register', [TechnicalController::class, 'registerMember']);
    Route::post('/login', [TechnicalController::class, 'loginMember']);
    Route::post('/deactivate', [TechnicalController::class, 'deactivateMember']);
    Route::post('/edit', [TechnicalController::class, 'editMember']);
    Route::post('/delete', [TechnicalController::class, 'deleteMember']);
    Route::post('/activate', [TechnicalController::class, 'activateMember']);
    Route::post('/changerole', [TechnicalController::class, 'changeRoleOfMember']);
});



