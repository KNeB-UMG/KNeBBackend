<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('members', function (Blueprint $table) {
            $table->id();
            $table->string('first_name');
            $table->string('last_name');
            $table->string('email')->unique();
            $table->string('password');
            $table->string('role')->default('user');
            $table->string('position')->nullable();
            $table->timestamp('deactivation_date')->nullable();
            $table->boolean('is_active')->default(true);
            $table->boolean('visible')->default(false);
            $table->string('photo')->nullable();
            $table->text('description')->nullable();
            $table->uuid('activation_code')->nullable();
            $table->uuid('password_reset_code')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
    }
};
