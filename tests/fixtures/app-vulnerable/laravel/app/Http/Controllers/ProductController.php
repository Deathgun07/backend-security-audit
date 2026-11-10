<?php
namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ProductController extends Controller
{
    public function index(Request $request)
    {
        return DB::select("SELECT * FROM products WHERE name LIKE '%{$request->q}%'");
    }

    public function update(Request $request, Product $product)
    {
        $product->update($request->all());
        return $product;
    }

    public function avatar(Request $request)
    {
        return $request->file('avatar')->storeAs('public', $request->file('avatar')->getClientOriginalName());
    }
}
