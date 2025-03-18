<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Post extends Model
{
    use HasFactory;

    protected $fillable = [
        'title',
        'content',
        'file_id',
        'author_id',
        'edit_history',
        'super_event',
        'visible'
    ];

    protected $casts = [
        'edit_history' => 'array',
        'super_event' => 'boolean',
        'visible' => 'boolean'
    ];

    public function author(): BelongsTo
    {
        return $this->belongsTo(Member::class, 'author_id');
    }

    public function file(): BelongsTo
    {
        return $this->belongsTo(File::class);
    }
}
