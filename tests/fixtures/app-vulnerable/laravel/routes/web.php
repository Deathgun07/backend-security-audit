<?php
use App\Http\Controllers\ProductController;
use Illuminate\Support\Facades\Route;

Route::get('/products', [ProductController::class, 'index']);
Route::post('/products/{product}', [ProductController::class, 'update'])->withoutMiddleware(['auth']);
Route::post('/avatar', [ProductController::class, 'avatar']);
