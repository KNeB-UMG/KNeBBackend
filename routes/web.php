<?php

use App\Http\Controllers\TechnicalController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});
Route::get('api/technical/basic', [TechnicalController::class, 'getBasic']);
