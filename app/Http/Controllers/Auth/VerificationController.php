<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use App\Providers\RouteServiceProvider;

class VerificationController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('throttle:6,1')->only('verify', 'resend');
    }

    public function verify(Request $request, User $user)
    {
        if(! URL::hasValidSignature($request)){
            return response()->json(["errors" => [
                "message" => "URLの有効期限が切れています。"
            ]], 422);
        }

        if($user->hasVerifiedEmail()){
            return response()->json(["errors" => [
                "message" => "メールアドレスは既に有効化されています。"
            ]], 422);
        }

        $user->markEmailAsVerified();
        event(new Verified($user));

        return response()->json(['message' => 'メールアドレスが有効化されました。'], 200);
    }

    public function resend(Request $request)
    {
        $this->validate($request, [
            'email' => ['email', 'required']
        ]);

        $user = User::where('email', $request->email)->first();
        if(! $user){
            return response()->json(["errors" => [
                "email" => "このメールアドレスを使用するユーザーが見つかりませんでした。"
            ]], 422);
        }

        if($user->hasVerifiedEmail()){
            return response()->json(["errors" => [
                "message" => "メールアドレスは既に有効化されています。"
            ]], 422);
        }

        $user->sendEmailVerificationNotification();

        return response()->json(['status' => "新しいURLを送信しました。"]);
    }
}
